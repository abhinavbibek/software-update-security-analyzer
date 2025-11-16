# simulation.py
import threading
import time
import logging
from datetime import datetime

logger = logging.getLogger("simulation")

# -------------------------------------------------------------------
# GLOBAL STATE
# -------------------------------------------------------------------
SIMULATION_STATE = {
    "status": "up_to_date",
    "type": None,
    "current_version": "1.0",
    "available_version": None,
    "in_progress_version": None,   # NEW: explicit slot for the version currently under analysis
    "message": "Your app is up to date. Current version: v1.0",
    "last_checked": datetime.utcnow().isoformat() + "Z",

    "update_available": False,
    "locked": False,
    "previous_version": None,        # helps in LLM comparison / history
}


# -------------------------------------------------------------------
# MAIN SIMULATION LOOP
# -------------------------------------------------------------------
def _simulate_ci_cd_updates():
    """
    Background CI/CD pipeline simulation.

    Correct behavior:
    - Website loads → shows up-to-date
    - After a pause announce next update (set available_version + update_available)
    - Wait for user to trigger analysis (/apply_update)
    - After analysis completes → WAIT again before next announcement
    """
    versions = ["1.1", "1.2"]
    idx = 0

    while True:
        # if analysis running, wait a short while and continue (do not overwrite state)
        if SIMULATION_STATE["locked"]:
            time.sleep(2)
            continue

        # Idle: clear any transient announcement but keep current_version stable
        SIMULATION_STATE.update({
            "status": "up_to_date",
            "available_version": None,
            "update_available": False,
            "in_progress_version": None,
            "message": f"Your app is up to date. Current version: v{SIMULATION_STATE['current_version']}",
            "last_checked": datetime.utcnow().isoformat() + "Z"
        })

        # Cooldown BEFORE releasing next update
        time.sleep(8)

        # If locked during wait, loop back
        if SIMULATION_STATE["locked"]:
            continue

        # If we've exhausted versions, remain idle but keep looping
        if idx >= len(versions):
            time.sleep(5)
            continue

        new_version = versions[idx]

        SIMULATION_STATE.update({
            "status": "update_available",
            "available_version": new_version,
            "update_available": True,
            "message": f"New update available: v{new_version}. Click 'Analyze Update' to begin malware analysis.",
            "last_checked": datetime.utcnow().isoformat() + "Z",
        })

        logger.info(f"[SIM] New update v{new_version} available.")

        # Wait for frontend user to trigger analysis. The frontend's /apply_update should set
        # SIMULATION_STATE['locked'] = True and optionally fill 'in_progress_version'.
        while SIMULATION_STATE["update_available"] and not SIMULATION_STATE["locked"]:
            time.sleep(1)

        # If the UI triggered analysis (locked now true), wait until the analysis finishes:
        while SIMULATION_STATE["locked"]:
            time.sleep(2)

        # After analysis completes → wait a bit then advance to the next version
        time.sleep(6)
        idx += 1


# -------------------------------------------------------------------
# API CONTROL FUNCTIONS
# -------------------------------------------------------------------
def mark_update_started(version: str = None):
    """
    Called when /apply_update is triggered.
    Accepts an optional version string: if provided, that version is recorded as the in-progress one.
    Important: do NOT aggressively clear available_version here — we keep it for transparency.
    """
    SIMULATION_STATE["locked"] = True
    SIMULATION_STATE["previous_version"] = SIMULATION_STATE.get("current_version")
    # If caller passed an explicit version, record it as the in-progress version.
    if version:
        SIMULATION_STATE["in_progress_version"] = version
    else:
        # If not provided, prefer the announced available_version (if any)
        SIMULATION_STATE["in_progress_version"] = SIMULATION_STATE.get("available_version")

    # Keep available_version present for a short time so frontends can still read which
    # version is being processed (helps avoid UI race). We do, however, turn off update_available
    # because the announcement is effectively consumed.
    SIMULATION_STATE["update_available"] = False
    SIMULATION_STATE["message"] = "Running malware analysis on the selected version..."
    SIMULATION_STATE["last_checked"] = datetime.utcnow().isoformat() + "Z"


def mark_update_completed():
    """
    Called after static analysis finishes.
    Use in_progress_version (if present) to update current_version.
    Unlock simulator and clear in_progress_version/available_version.
    """
    SIMULATION_STATE["locked"] = False

    # Prefer explicit in-progress version (the one accepted for analysis).
    in_prog = SIMULATION_STATE.get("in_progress_version")
    if in_prog:
        SIMULATION_STATE["current_version"] = in_prog
    else:
        # fallback to whatever was announced (if any)
        if SIMULATION_STATE.get("available_version"):
            SIMULATION_STATE["current_version"] = SIMULATION_STATE["available_version"]

    # reset transient fields and report completion
    SIMULATION_STATE["message"] = (
        f"Analysis completed. App is now up to date (v{SIMULATION_STATE['current_version']})."
    )
    SIMULATION_STATE["available_version"] = None
    SIMULATION_STATE["in_progress_version"] = None
    SIMULATION_STATE["update_available"] = False
    SIMULATION_STATE["status"] = "up_to_date"
    SIMULATION_STATE["last_checked"] = datetime.utcnow().isoformat() + "Z"


# -------------------------------------------------------------------
# THREAD LAUNCHER
# -------------------------------------------------------------------
_SIM_THREAD_STARTED = False

def start_simulation_thread():
    """Start CI/CD simulation only once."""
    global _SIM_THREAD_STARTED
    if _SIM_THREAD_STARTED:
        return
    thread = threading.Thread(target=_simulate_ci_cd_updates, daemon=True)
    thread.start()
    _SIM_THREAD_STARTED = True
    logger.info("Simulation background task started.")


# Auto-start simulation
start_simulation_thread()

# Compatibility alias
start_auto_simulation = start_simulation_thread
