import os
import asyncio
import json
import logging
from datetime import datetime

from src.server.analyzer.static_dark_report import run_pipeline
from src.server.utils import ensure_dir, record_progress

logger = logging.getLogger("reporter")


# ------------------------------------------------------------
# Helper — run static analysis for one ZIP
# ------------------------------------------------------------
async def _run_single(zip_path, out_dir, run_id):
    record_progress(run_id, f"Extracting + scanning {os.path.basename(zip_path)}", 10)
    await asyncio.to_thread(run_pipeline, zip_path, out_dir, True, 4, run_id)
    record_progress(run_id, f"Completed {os.path.basename(zip_path)}", 100)


# ------------------------------------------------------------
# 1) Manual Compare: Analyzes TWO versions (old + new)
# ------------------------------------------------------------
async def generate_reports_for_update(simulated=False, v1_zip=None, v2_zip=None, run_id=None):
    """
    This function is ONLY used for manual compare AND old legacy flows.
    It analyzes TWO ZIP files:
        - v1_zip   → old version
        - v2_zip   → new version
    It writes both outputs into:
        reports/<run_id>/v1_update
        reports/<run_id>/v2_update
    """

    run_label = run_id or datetime.utcnow().strftime("run_%Y%m%d_%H%M%S")
    out_dir = os.path.join("reports", run_label)
    ensure_dir(out_dir)

    # For legacy-simulated usage
    if simulated:
        v1_zip = v1_zip or "samples/notepad_v1.zip"
        v2_zip = v2_zip or "samples/notepad_v2.zip"

    if not v1_zip or not v2_zip:
        raise ValueError("Both v1_zip and v2_zip must be provided for manual compare")

    v1_out = os.path.join(out_dir, "v1_update")
    v2_out = os.path.join(out_dir, "v2_update")
    ensure_dir(v1_out)
    ensure_dir(v2_out)

    # # v1 analysis
    # record_progress(run_label, "Analyzing Version 1", 5)
    # await asyncio.to_thread(run_pipeline, v1_zip, v1_out, True, 4, run_label)

    # record_progress(run_label, "Version 1 analysis complete", 50)

    # # v2 analysis
    # record_progress(run_label, "Analyzing Version 2", 55)
    # await asyncio.to_thread(run_pipeline, v2_zip, v2_out, True, 4, run_label)

    # record_progress(run_label, "Version 2 analysis complete", 95)

    # Save metadata
    combined_meta = {
        "run_id": run_label,
        "generated": datetime.utcnow().isoformat() + "Z",
        "v1_report": v1_out,
        "v2_report": v2_out,
    }

    with open(os.path.join(out_dir, "run_metadata.json"), "w") as f:
        json.dump(combined_meta, f, indent=2)

    # record_progress(run_label, "Analysis complete!", 100)

    logger.info(f"[Manual Compare] Completed run {run_label}")

    return out_dir


# ------------------------------------------------------------
# 2) NEW SINGLE-VERSION ANALYSIS (Used by /apply_update)
# ------------------------------------------------------------
async def generate_single_report(zip_path, out_dir, run_id):
    """
    This is used by /apply_update for analyzing ONLY ONE UPDATE.
    Writes results in:
        /app/reports/current_run/<name>_update
    """

    ensure_dir(out_dir)

    # record_progress(run_id, "Starting static analysis...", 5)
    await asyncio.to_thread(run_pipeline, zip_path, out_dir, True, 4, run_id)

    logger.info(f"[Single Update] Generated report: {out_dir}")
    return out_dir
