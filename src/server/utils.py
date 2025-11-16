# versiondiff-sentinel/src/server/utils.py
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("utils")

# ---------------------------------------------------------
# GLOBAL PROGRESS STORAGE
# ---------------------------------------------------------
PROGRESS_STATE = {}

# Only used if backend explicitly wants a "global" run
DEFAULT_RUN_ID = "global_update"


def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _make_entry(run_id, step, percent):
    return {
        "run_id": run_id,
        "step": step,
        "message": step,
        "percent": int(percent),
        "ts": _now_iso(),
    }


# -------------------------------------------------------------------------
# NEW: Strict + safe record_progress
# -------------------------------------------------------------------------
def record_progress(run_id, step=None, percent=None, only_get=False):
    """
    STRICT mode (predictable behavior):

    GET PROGRESS:
        record_progress(run_id, only_get=True)

    SET PROGRESS:
        record_progress(run_id, "Extracting ZIP", 10)

    No more "smart" guessing or overloaded behaviors.
    """

    # -----------------------------------------------------
    # GET MODE
    # -----------------------------------------------------
    if only_get:
        entry = PROGRESS_STATE.get(run_id)
        if not entry:
            return _make_entry(run_id, "idle", 0)
        return entry

    # -----------------------------------------------------
    # SET MODE MUST be: (run_id, step, percent)
    # -----------------------------------------------------
    if step is None or percent is None:
        raise ValueError(
            f"record_progress(run_id, step, percent) requires explicit step+percent. "
            f"Received: run_id={run_id}, step={step}, percent={percent}"
        )

    percent = int(percent)
    entry = _make_entry(run_id, step, percent)
    PROGRESS_STATE[run_id] = entry

    # Logging
    logger.info(f"[Progress] {run_id} - {step} ({percent}%)")

    # Append to log (best effort)
    try:
        ensure_dir("reports")
        with open("reports/progress_log.json", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to write progress log: {e}")

    return entry
