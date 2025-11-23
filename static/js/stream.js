// static/js/stream.js
// Robust MediaRecorder uploader: waits for full blob, skips tiny blobs, posts as video_chunk
(() => {
  const SID = window.SID || "no-sid";
  const videoEl = document.getElementById("video");
  const startBtn = document.getElementById("startBtn");
  const stopBtn = document.getElementById("stopBtn");
  const captureBtn = document.getElementById("captureBtn");
  const recordBtn = document.getElementById("recordBtn");

  let mediaStream = null;
  let recorder = null;
  let chunkIndex = 0;

  // Simple upload concurrency limiter (keeps server healthy)
  const MAX_CONCURRENT_UPLOADS = 3;
  let uploadsInFlight = 0;
  const uploadQueue = [];

  function enqueueUpload(fn) {
    return new Promise((resolve, reject) => {
      const job = async () => {
        uploadsInFlight++;
        try {
          const r = await fn();
          resolve(r);
        } catch (e) {
          reject(e);
        } finally {
          uploadsInFlight--;
          if (uploadQueue.length) {
            const next = uploadQueue.shift();
            next();
          }
        }
      };

      if (uploadsInFlight < MAX_CONCURRENT_UPLOADS) {
        job();
      } else {
        uploadQueue.push(job);
      }
    });
  }

  // Choose video mime like original but safe
  function chooseVideoMime() {
    let mime = "video/webm;codecs=vp9,opus";
    if (!MediaRecorder.isTypeSupported(mime)) {
      mime = "video/webm;codecs=vp8,opus";
      if (!MediaRecorder.isTypeSupported(mime)) mime = "video/webm";
    }
    return mime;
  }

  // Choose audio mime (try common ones)
  function chooseAudioMime() {
    const candidates = [
      "audio/webm;codecs=opus",
      "audio/webm",
      "audio/ogg;codecs=opus",
      "audio/ogg",
    ];
    for (const c of candidates) {
      if (MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(c)) return c;
    }
    return undefined;
  }

  async function startCamera() {
    try {
      startBtn.disabled = true;

      mediaStream = await navigator.mediaDevices.getUserMedia({ video: { width:720, height:1280 }, audio: true });
      videoEl.srcObject = mediaStream;
      videoEl.muted = false;

      captureBtn.disabled = true;
      videoEl.onloadedmetadata = () => {
        if (videoEl.videoWidth && videoEl.videoHeight) {
          captureBtn.disabled = false;
        }
      };
      await videoEl.play();

      startStreaming();

      stopBtn.disabled = false;
      startBtn.disabled = true;
    } catch (e) {
      startBtn.disabled = false;
      alert("Camera/mic access failed: " + (e && e.message ? e.message : e));
      console.error(e);
    }
  }

  function stopCamera() {
    try {
      if (recorder && recorder.state !== "inactive") {
        try { recorder.stop(); } catch(e) { console.warn("recorder stop failed", e); }
      }
      if (mediaStream) {
        mediaStream.getTracks().forEach(t => t.stop());
      }
      recorder = null;
      mediaStream = null;
      stopBtn.disabled = true;
      startBtn.disabled = false;
      captureBtn.disabled = true;
    } catch (e) { console.warn(e); }
  }

  startBtn.addEventListener("click", startCamera);
  stopBtn.addEventListener("click", stopCamera);

  // capture photo
  captureBtn.addEventListener("click", async () => {
    if (!mediaStream) { alert("Start camera first"); return; }
    const w = videoEl.videoWidth || 720;
    const h = videoEl.videoHeight || 1280;
    if (!w || !h) { alert("Video not ready yet"); return; }

    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    const ctx = c.getContext("2d");
    ctx.drawImage(videoEl, 0, 0, c.width, c.height);

    c.toBlob(async (blob) => {
      if (!blob || blob.size === 0) { alert("Capture failed"); return; }
      const fd = new FormData();
      fd.append("sid", SID);
      fd.append("photo", blob, "photo.jpg");
      try {
        await enqueueUpload(() => fetch("/upload_photo", { method: "POST", body: fd }));
        alert("Photo uploaded");
      } catch (e) {
        console.error(e);
        alert("Upload failed");
      }
    }, "image/jpeg", 0.9);
  });

  // audio recording (10s auto stop - same as your last version)
  recordBtn.addEventListener("click", async () => {
    try {
      const s = await navigator.mediaDevices.getUserMedia({ audio: true });
      const audioMime = chooseAudioMime();
      let mr;
      try {
        if (audioMime) mr = new MediaRecorder(s, { mimeType: audioMime });
        else mr = new MediaRecorder(s);
      } catch (ex) {
        try { mr = new MediaRecorder(s); } catch (ex2) {
          s.getTracks().forEach(t => t.stop());
          throw ex2;
        }
      }

      const parts = [];
      mr.ondataavailable = e => { if (e.data && e.data.size) parts.push(e.data); };
      mr.onerror = (err) => console.error("Audio recorder error", err);
      mr.onstop = async () => {
        try {
          const blob = new Blob(parts, { type: audioMime || "audio/webm" });
          const fd = new FormData();
          fd.append("sid", SID);
          fd.append("audio", blob, "clip.webm");
          try {
            await enqueueUpload(() => fetch("/upload_audio", { method: "POST", body: fd }));
            alert("Audio uploaded");
          } catch (e) {
            console.error("Audio upload failed", e);
            alert("Upload failed");
          }
        } finally {
          s.getTracks().forEach(t => t.stop());
        }
      };

      try {
        mr.start();
      } catch (e) {
        s.getTracks().forEach(t => t.stop());
        throw e;
      }
      setTimeout(() => {
        try { if (mr.state !== "inactive") mr.stop(); } catch(e) { console.warn("mr.stop failed", e); }
      }, 10000); // 10s
    } catch (e) {
      alert("Mic failed: " + (e && e.message ? e.message : e));
      console.error(e);
    }
  });

  function startStreaming() {
    if (!mediaStream) return;

    const mime = chooseVideoMime();

    chunkIndex = 0;
    try {
      recorder = new MediaRecorder(mediaStream, { mimeType: mime, videoBitsPerSecond: 800000, audioBitsPerSecond: 64000 });
    } catch (e) {
      try {
        recorder = new MediaRecorder(mediaStream);
      } catch (err) {
        console.error("Failed to create MediaRecorder for video", err);
        return;
      }
    }

    recorder.ondataavailable = (event) => {
      try {
        if (!event.data || event.data.size === 0) return;
        const size = event.data.size;
        if (size < 20 * 1024) { // skip tiny blobs (20 KB)
          console.warn("Skipping tiny chunk:", size);
          return;
        }

        const blob = event.data;
        const filename = String(chunkIndex).padStart(6, "0") + ".webm";
        const fd = new FormData();
        fd.append("sid", SID);
        // append chunk with a filename so server can inspect Content-Disposition if needed
        fd.append("video_chunk", blob, filename);

        // enqueue upload to avoid flooding server
        enqueueUpload(() => fetch("/stream_video", { method: "POST", body: fd }).catch(e => {
          console.error("Upload failed", e);
        }));

        chunkIndex++;
      } catch (err) {
        console.error("ondataavailable error:", err);
      }
    };

    recorder.onerror = (e) => console.error("Recorder error", e);

    try {
      recorder.start(2000); // 2s chunks (unchanged)
      console.log("Recorder started, mime:", mime);
    } catch (e) {
      console.error("recorder.start() failed", e);
    }
  }

  // graceful stop on unload — allow a short grace period for last chunk to be processed
  window.addEventListener("beforeunload", (ev) => {
    try {
      if (recorder && recorder.state !== "inactive") {
        try { recorder.stop(); } catch (e) { console.warn(e); }
        const start = Date.now();
        while (Date.now() - start < 150) { /* spin briefly */ }
      }
    } catch (e) {}
  });
})();
