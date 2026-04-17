"""
Web interface for the Network Forensic Pipeline.

Features:
  - PCAP file upload (drag-and-drop)
  - Pipeline configuration and execution
  - Live log streaming via Server-Sent Events (SSE)
  - Metrics dashboard
  - Results browser with full report viewer

Run:
    pip install flask
    python3 web_app.py
Then open http://localhost:5000
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, stream_with_context, url_for,
)
from werkzeug.utils import secure_filename

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.resolve()
INPUT_DIR  = BASE_DIR / "input_pcaps"
OUTPUT_DIR = BASE_DIR / "agent_outputs"
METRICS_FILE = BASE_DIR / "pipeline_run_metrics.json"
DB_PATH    = BASE_DIR / "evidence_registry.db"

INPUT_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024  # 2 GB

# ── Pipeline state (shared across threads) ────────────────────────────────────
pipeline_state = {
    "running": False,
    "pid": None,
    "started_at": None,
    "phase": None,
    "exit_code": None,
}
state_lock = threading.Lock()

# Per-client log queues: client_id -> queue.Queue
log_queues: Dict[str, queue.Queue] = {}
log_queues_lock = threading.Lock()

# Ring buffer of the last 500 log lines (for late-joining clients)
LOG_BUFFER_MAX = 500
log_buffer: List[str] = []
log_buffer_lock = threading.Lock()


def broadcast_log(line: str):
    """Push a log line to all connected SSE clients and the ring buffer."""
    with log_buffer_lock:
        log_buffer.append(line)
        if len(log_buffer) > LOG_BUFFER_MAX:
            log_buffer.pop(0)

    with log_queues_lock:
        dead = []
        for cid, q in log_queues.items():
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(cid)
        for cid in dead:
            del log_queues[cid]


def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


# ── Routes: Upload ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("upload_page"))


@app.route("/upload")
def upload_page():
    files = sorted(
        [
            {
                "name": f.name,
                "size_mb": round(f.stat().st_size / 1_048_576, 2),
                "modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
            }
            for f in INPUT_DIR.iterdir()
            if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS
        ],
        key=lambda x: x["name"],
    )
    return render_template("upload.html", files=files)


@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded = request.files.getlist("pcap_files")
    results = []

    for f in uploaded:
        if not f or not f.filename:
            continue
        if not allowed_file(f.filename):
            results.append({"name": f.filename, "ok": False, "msg": "Not a pcap/pcapng file"})
            continue

        filename = secure_filename(f.filename)
        dest = INPUT_DIR / filename
        f.save(dest)
        size_mb = round(dest.stat().st_size / 1_048_576, 2)
        results.append({"name": filename, "ok": True, "size_mb": size_mb})

    return jsonify({"results": results})


@app.route("/upload/delete", methods=["POST"])
def delete_file():
    filename = request.json.get("filename", "")
    if not filename:
        return jsonify({"ok": False, "msg": "No filename"})
    target = INPUT_DIR / secure_filename(filename)
    if target.exists() and target.parent == INPUT_DIR:
        target.unlink()
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "File not found"})


@app.route("/api/files")
def api_files():
    files = [
        {
            "name": f.name,
            "size_mb": round(f.stat().st_size / 1_048_576, 2),
            "modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
        for f in INPUT_DIR.iterdir()
        if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS
    ]
    return jsonify(sorted(files, key=lambda x: x["name"]))


# ── Routes: Pipeline ───────────────────────────────────────────────────────────

@app.route("/pipeline")
def pipeline_page():
    with state_lock:
        state = dict(pipeline_state)
    return render_template("pipeline.html", state=state)


@app.route("/api/pipeline/status")
def pipeline_status():
    with state_lock:
        return jsonify(dict(pipeline_state))


@app.route("/api/pipeline/start", methods=["POST"])
def pipeline_start():
    with state_lock:
        if pipeline_state["running"]:
            return jsonify({"ok": False, "msg": "Pipeline already running"}), 409

    data = request.json or {}
    start_phase  = int(data.get("start_phase", 1))
    end_phase    = int(data.get("end_phase", 9))
    workers      = int(data.get("workers", 1))
    agentic      = bool(data.get("agentic", False))
    ollama_model = data.get("ollama_model", "llama3.1")
    clear        = bool(data.get("clear", False))

    cmd = [
        sys.executable, str(BASE_DIR / "pipeline_runner.py"),
        "--db-path", str(DB_PATH),
        "--input-dir", str(INPUT_DIR),
        "--agent-outdir", str(OUTPUT_DIR),
        "--start-phase", str(start_phase),
        "--end-phase",   str(end_phase),
        "--step5-workers", str(workers),
    ]
    if clear:
        cmd.append("--clear")
    if agentic:
        cmd += ["--agentic", "--ollama-model", ollama_model]

    def run_pipeline(cmd):
        with state_lock:
            pipeline_state["running"]    = True
            pipeline_state["started_at"] = datetime.now(timezone.utc).isoformat()
            pipeline_state["exit_code"]  = None
            pipeline_state["phase"]      = f"Phase {start_phase}–{end_phase}"

        with log_buffer_lock:
            log_buffer.clear()

        broadcast_log(f"[WEB] Starting pipeline: {' '.join(cmd)}\n")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(BASE_DIR),
        )

        with state_lock:
            pipeline_state["pid"] = proc.pid

        for line in iter(proc.stdout.readline, ""):
            broadcast_log(line)

        proc.wait()
        exit_code = proc.returncode

        broadcast_log(f"\n[WEB] Pipeline finished with exit code {exit_code}\n")
        broadcast_log("__DONE__")  # sentinel for clients

        with state_lock:
            pipeline_state["running"]   = False
            pipeline_state["exit_code"] = exit_code
            pipeline_state["pid"]       = None

    t = threading.Thread(target=run_pipeline, args=(cmd,), daemon=True)
    t.start()

    return jsonify({"ok": True, "msg": "Pipeline started"})


@app.route("/api/pipeline/stop", methods=["POST"])
def pipeline_stop():
    with state_lock:
        pid = pipeline_state.get("pid")
        if not pid:
            return jsonify({"ok": False, "msg": "No running pipeline"})

    try:
        import signal
        os.kill(pid, signal.SIGTERM)
        broadcast_log("\n[WEB] Pipeline stop requested.\n")
        broadcast_log("__DONE__")
        with state_lock:
            pipeline_state["running"] = False
        return jsonify({"ok": True})
    except ProcessLookupError:
        return jsonify({"ok": False, "msg": "Process not found"})


@app.route("/api/pipeline/logs")
def pipeline_logs_sse():
    """Server-Sent Events endpoint — streams live pipeline output."""
    client_id = str(time.time())
    q: queue.Queue = queue.Queue(maxsize=2000)

    # Send the ring buffer first so late-joiners see historical logs
    with log_buffer_lock:
        snapshot = list(log_buffer)
    with log_queues_lock:
        log_queues[client_id] = q

    def generate():
        # Replay historical buffer
        for line in snapshot:
            yield f"data: {json.dumps(line)}\n\n"

        # Then stream new lines
        while True:
            try:
                line = q.get(timeout=20)
                yield f"data: {json.dumps(line)}\n\n"
                if line == "__DONE__":
                    break
            except queue.Empty:
                yield "data: null\n\n"  # heartbeat

        with log_queues_lock:
            log_queues.pop(client_id, None)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Routes: Metrics ────────────────────────────────────────────────────────────

@app.route("/metrics")
def metrics_page():
    return render_template("metrics.html")


@app.route("/api/metrics")
def api_metrics():
    if not METRICS_FILE.exists():
        return jsonify({"error": "No metrics file found yet"}), 404
    with METRICS_FILE.open() as f:
        data = json.load(f)
    return jsonify(data)


# ── Routes: Results ────────────────────────────────────────────────────────────

@app.route("/results")
def results_page():
    return render_template("results.html")


@app.route("/api/results")
def api_results():
    bundles = []
    if OUTPUT_DIR.exists():
        for child in sorted(OUTPUT_DIR.iterdir()):
            if not child.is_dir() or child.name in {"campaign", "master"}:
                continue
            report_path = child / "report.json"
            if not report_path.exists():
                continue
            try:
                with report_path.open() as f:
                    data = json.load(f)
                m = data.get("metrics", {})
                bundles.append({
                    "bundle_id": data.get("bundle_id", child.name),
                    "finding_count": m.get("finding_count", 0),
                    "hypothesis_count": m.get("hypothesis_count", 0),
                    "event_count": m.get("event_count", 0),
                    "pcap_count": m.get("pcap_count", 0),
                    "runtime_seconds": m.get("analysis_runtime_seconds", 0),
                    "agentic_mode": m.get("agentic_mode", False),
                })
            except Exception:
                pass
    return jsonify(bundles)


@app.route("/api/results/<bundle_id>")
def api_result_detail(bundle_id):
    report_path = OUTPUT_DIR / bundle_id / "report.json"
    if not report_path.exists():
        return jsonify({"error": "Report not found"}), 404
    with report_path.open() as f:
        return jsonify(json.load(f))


@app.route("/results/<bundle_id>")
def result_detail_page(bundle_id):
    return render_template("report_detail.html", bundle_id=bundle_id)


@app.route("/api/results/<bundle_id>/markdown")
def api_result_markdown(bundle_id):
    md_path = OUTPUT_DIR / bundle_id / "report.md"
    if not md_path.exists():
        return jsonify({"error": "Markdown not found"}), 404
    return Response(md_path.read_text(), mimetype="text/plain")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting Network Forensic Web Interface...")
    print(f"  Input PCAPs : {INPUT_DIR}")
    print(f"  Agent output: {OUTPUT_DIR}")
    print(f"  Database    : {DB_PATH}")
    print()
    print("Open http://localhost:5000 in your browser")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
