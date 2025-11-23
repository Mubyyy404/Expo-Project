#!/usr/bin/env python3
import os
import json
import datetime
import uuid
import subprocess
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename

# --------------------- Fix directory paths ---------------------
BASE = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(BASE, "logs.json")
UPLOAD_DIR = os.path.join(BASE, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --------------------- Flask app setup ---------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max upload


# --------------------- Helper: log events ---------------------
def log_event(obj):
    if not os.path.exists(LOGFILE):
        with open(LOGFILE, "w") as f:
            json.dump([], f)

    with open(LOGFILE, "r+", encoding="utf-8") as f:
        try:
            arr = json.load(f)
        except json.JSONDecodeError:
            arr = []
        arr.append(obj)
        f.seek(0)
        f.truncate()
        json.dump(arr, f, indent=2, ensure_ascii=False)


# --------------------- Routes ---------------------
@app.route("/")
def index():
    return redirect(url_for('start'))


@app.route("/start")
def start():
    sid = str(uuid.uuid4())
    return redirect(url_for('consent', sid=sid))


@app.route("/consent/<sid>")
def consent(sid):
    return render_template("consent.html", sid=sid)


@app.route("/demo/<sid>")
def demo(sid):
    return render_template("demo.html", sid=sid)


@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    data = request.get_json(silent=True) or {}
    data["_ts"] = datetime.datetime.now().isoformat()
    data["_ip"] = request.remote_addr or "unknown"
    log_event({"type": "fingerprint", "sid": data.get("sid"), "data": data})
    return jsonify({"ok": True})


# --------------------- FIXED stream_video: APPEND MODE ---------------------
@app.route("/stream_video", methods=["POST"])
def stream_video():
    sid = request.form.get("sid", "unknown")

    # Expect a multipart FormData field "video_chunk"
    if 'video_chunk' not in request.files:
        return "", 400

    chunk = request.files['video_chunk']
    data = chunk.read()

    # Skip extremely tiny chunks that are likely empty/corrupt
    # (This threshold is conservative; adjust if you see false positives)
    MIN_BYTES = 2 * 1024  # 2 KB
    if len(data) < MIN_BYTES:
        log_event({
            "type": "video_chunk_skipped",
            "sid": sid,
            "size": len(data),
            "reason": "too_small",
            "ts": datetime.datetime.now().isoformat()
        })
        return "", 204

    # Ensure session directory exists
    session_dir = os.path.join(UPLOAD_DIR, f"{sid}_stream")
    os.makedirs(session_dir, exist_ok=True)

    # Final combined filename (Mode A)
    final_path = os.path.join(session_dir, "final.webm")

    # Append the raw chunk bytes into the single file
    # Use atomic append via opening in 'ab' mode
    try:
        with open(final_path, "ab") as f:
            f.write(data)
    except Exception as e:
        log_event({
            "type": "video_chunk_error",
            "sid": sid,
            "error": str(e),
            "ts": datetime.datetime.now().isoformat()
        })
        return "", 500

    # Optional lite validation via ffprobe if available (non-blocking)
    valid = True
    try:
        # Run ffprobe only on small chance to avoid repeated calls;
        # we will call it only if file size exceeds a threshold (e.g. 40KB)
        if os.path.getsize(final_path) > 40 * 1024:
            result = subprocess.run(
                ["ffprobe", "-v", "error", final_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=6
            )
            if result.returncode != 0:
                # Do not treat as fatal — log and continue appending (some fragments may be incomplete until finalization)
                valid = False
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        # ffprobe not present or error — accept and continue
        valid = True

    log_event({
        "type": "video_chunk",
        "sid": sid,
        "size": len(data),
        "filename": "final.webm",
        "valid_ffprobe": valid,
        "ts": datetime.datetime.now().isoformat()
    })

    # Return 200 to indicate chunk accepted
    return "", 200


@app.route("/perm_event", methods=["POST"])
def perm_event():
    data = request.get_json(silent=True) or {}
    data["_ts"] = datetime.datetime.now().isoformat()
    data["_ip"] = request.remote_addr or "unknown"
    log_event({"type": "perm_event", "sid": data.get("sid"), "data": data})
    return jsonify({"ok": True})


@app.route("/upload_photo", methods=["POST"])
def upload_photo():
    sid = request.form.get("sid", "no-sid")
    if 'photo' not in request.files:
        return jsonify({"ok": False, "error": "no file"}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({"ok": False, "error": "empty filename"}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in {'.jpg', '.jpeg', '.png', '.webp', '.heic'}:
        ext = '.jpg'

    filename = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f") + "_" + sid + ext
    path = os.path.join(UPLOAD_DIR, secure_filename(filename))
    file.save(path)

    log_event({"type": "photo_upload", "sid": sid, "filename": filename})
    return jsonify({"ok": True, "filename": filename})


@app.route("/upload_audio", methods=["POST"])
def upload_audio():
    sid = request.form.get("sid", "no-sid")
    if 'audio' not in request.files:
        return jsonify({"ok": False}), 400

    file = request.files['audio']
    filename = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f") + "_" + sid + ".webm"
    path = os.path.join(UPLOAD_DIR, secure_filename(filename))
    file.save(path)

    log_event({"type": "audio_upload", "sid": sid, "filename": filename})
    return jsonify({"ok": True})


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/admin")
def admin():
    return render_template("admin.html")


@app.route("/admin/logs")
def admin_logs():
    if not os.path.exists(LOGFILE):
        return jsonify([])
    try:
        with open(LOGFILE, encoding="utf-8") as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])


# --------------------- Run server ---------------------
if __name__ == "__main__":
    ip = "0.0.0.0"
    port = 5000
    print(f"\nServer running → http://{ip}:{port}\n")
    app.run(host=ip, port=port, debug=False, threaded=True)
