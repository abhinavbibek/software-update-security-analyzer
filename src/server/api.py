# api.py
import os
import json
import logging
import shutil
import uuid
import time
import asyncio
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from src.server.utils import ensure_dir, record_progress, DEFAULT_RUN_ID

from src.server.simulation import (
    SIMULATION_STATE,
    mark_update_started,
    mark_update_completed,
)
from src.server.reporter import generate_reports_for_update
from src.server.llm_analyzer import run_llm_analysis
from src.server.analyzer.static_dark_report import run_pipeline as run_dark_pipeline

logger = logging.getLogger("api")
router = APIRouter()

REPORTS_BASE = os.environ.get("REPORTS_BASE", "/app/reports")
SAMPLES_BASE = "samples"


# --------------------------------------------------------
# STATIC ANALYSIS WRAPPER
# --------------------------------------------------------
def perform_static_analysis(zip_path: str, out_dir: str, run_id: str = None):
    """
    Small wrapper around the core static analysis pipeline that records
    frontend-visible progress and returns the results dict from the pipeline.
    """
    os.makedirs(out_dir, exist_ok=True)
    run_id = run_id or DEFAULT_RUN_ID

    # # Frontend-visible progress stages (now using normalized run_id)
    # record_progress(run_id, "Extracting ZIP contents...", 10)
    # time.sleep(0.8)

    # record_progress(run_id, "Scanning binaries and files...", 40)
    # time.sleep(0.8)

    # record_progress(run_id, "Running deep malware analysis...", 70)
    # time.sleep(0.8)

    logger.info(f"[+] Running Static Analysis on: {zip_path}")
    results = run_dark_pipeline(zip_path, out_dir, analyze_all=True, workers=4, run_id=run_id)


    time.sleep(0.5)
    logger.info(f"[+] Dark report generated at: {results.get('reports_dir', out_dir)}")

    return results


# --------------------------------------------------------
# ROUTES
# --------------------------------------------------------
@router.get("/check_update")
async def check_update():
    """Return current CI/CD simulation state"""
    return JSONResponse(SIMULATION_STATE)


# --------------------------------------------------------
# MANUAL ZIP UPLOAD (unchanged)
# --------------------------------------------------------
@router.post("/upload_zip")
async def upload_zip(version: str = Form(...), file: UploadFile = File(...)):
    try:
        base_dir = f"/app/data/uploads/{version}"
        os.makedirs(base_dir, exist_ok=True)

        zip_path = os.path.join(base_dir, file.filename)
        with open(zip_path, "wb") as f:
            f.write(await file.read())

        output_dir = f"/app/reports/{version}_update"
        result = perform_static_analysis(zip_path, output_dir)

        return {
            "message": f"Analysis completed for {version}",
            "reports": result,
            "output_dir": output_dir,
            "ai_ready": True,
        }

    except Exception as e:
        logger.exception("Upload ZIP analysis failed")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------
# LIST SAMPLES (unchanged)
# --------------------------------------------------------
@router.get("/samples")
async def list_samples():
    try:
        files = [f for f in os.listdir(SAMPLES_BASE) if f.endswith(".zip")]
    except Exception as e:
        logger.error(f"Error reading samples: {e}")
        files = []
    return {"samples": files}


# --------------------------------------------------------
# MAIN UPDATE ANALYSIS (TRIGGERED BY BUTTON ONLY)
# --------------------------------------------------------
@router.post("/apply_update")
async def apply_update(version: str = Form(None)):
    run_id = f"run_{uuid.uuid4().hex[:8]}"

    try:
        # Early progress marker
        record_progress(run_id, "Starting update analysis...", 5)

        # Determine which version to analyze
        available_version = SIMULATION_STATE.get("available_version")
        if version:
            target = version
        elif available_version:
            target = available_version
        else:
            target = "notepad_v1.zip"

        # Now lock and store the version under analysis
        mark_update_started(version=str(target))



        # ---------------------------
        # Normalize `target` to an actual ZIP file path (candidate)
        # ---------------------------
        def try_candidates(basename_candidates):
            """Return the first existing candidate path (absolute or relative) or None."""
            for c in basename_candidates:
                # absolute candidate
                if os.path.isabs(c) and os.path.exists(c):
                    return c
                # /app/samples canonical location
                app_sample = os.path.join("/app/samples", os.path.basename(c))
                if os.path.exists(app_sample):
                    return app_sample
                # development samples/ next to the repo
                dev_sample = os.path.join("samples", os.path.basename(c))
                if os.path.exists(dev_sample):
                    return dev_sample
            return None

        # Make a prioritized list of possible filenames/paths to try
        candidates_to_try = []
        if target.lower().endswith(".zip"):
            candidates_to_try.append(target)
        else:
            tv = target.lower().lstrip("v")
            if tv.replace(".", "", 1).isdigit():
                # Map versions directly to sample names
                version_map = {
                    "1.0": "notepad_v1.zip",
                    "1.1": "notepad_v1.zip",
                    "1.2": "notepad_v2.zip",
                }

# Always try directly using version_map first
                if tv in version_map:
                    candidates_to_try.append(version_map[tv])

            candidates_to_try.append(target)
            candidates_to_try.append(os.path.join("samples", target))

        candidate = try_candidates(candidates_to_try)

        if not candidate:
            tried = ", ".join([os.path.join("/app/samples", os.path.basename(c)) for c in candidates_to_try])
            # ensure we release lock if sample missing
            try:
                mark_update_completed()
            except Exception:
                SIMULATION_STATE["locked"] = False
            raise FileNotFoundError(
                f"Update sample not found. Tried: {tried} — please place the sample ZIP in /app/samples or upload it."
            )

        if not os.path.exists(candidate):
            dev_candidate = os.path.join("samples", os.path.basename(candidate))
            if os.path.exists(dev_candidate):
                candidate = dev_candidate
            else:
                try:
                    mark_update_completed()
                except Exception:
                    SIMULATION_STATE["locked"] = False
                raise FileNotFoundError(f"Update sample not found: {candidate}")

        # Make the output directory deterministic for this run
        output_dir = os.path.join("/app/reports/current_run", os.path.splitext(os.path.basename(candidate))[0] + "_update")
        os.makedirs(output_dir, exist_ok=True)

        # At this point we have resolved the candidate path synchronously.
        # Spawn the heavy work in background and return immediately with run_id.

        async def _background_work(candidate_path, out_dir, rid):
            try:
                await asyncio.to_thread(perform_static_analysis, candidate_path, out_dir, rid)

                # 🔥 FIX: Explicitly send completion progress
                record_progress(rid, "Analysis completed.", 100)

            except Exception as exc:
                logger.exception(f"Background analysis failed for {rid}")
                record_progress(rid, f"Analysis failed: {exc}", 0)

            finally:
                try:
                    mark_update_completed()
                except Exception:
                    SIMULATION_STATE["locked"] = False


        # schedule the background task and return
        asyncio.create_task(_background_work(candidate, output_dir, run_id))

        reports_base = "/app/reports/current_run"
        return JSONResponse(
            {
                "status": "analysis_started",
                "reports_base": reports_base,
                "analyzed_version": os.path.basename(candidate),
                "run_id": run_id,
                "ai_ready": False,
            },
            status_code=202,
        )

    except Exception as e:
        logger.exception("Apply update failed")
        # ensure we release lock if anything goes wrong
        try:
            mark_update_completed()
        except Exception:
            SIMULATION_STATE["locked"] = False
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------
# MANUAL COMPARE (unchanged)
# --------------------------------------------------------
@router.post("/analyze")
async def manual_analyze(
    old_file: UploadFile = File(None),
    new_file: UploadFile = File(None),
    sample_old: str = Form(None),
    sample_new: str = Form(None),
    out_dir_name: str = Form(None),
):
    run_id = out_dir_name or f"run_{uuid.uuid4().hex[:8]}"
    out_base = os.path.join(REPORTS_BASE, run_id)
    ensure_dir(out_base)

    def save_upload(upload, filename):
        if not upload:
            return None
        dest = os.path.join(out_base, filename)
        with open(dest, "wb") as f:
            shutil.copyfileobj(upload.file, f)
        return dest

    try:
        old_path = (
            save_upload(old_file, "old.zip")
            if old_file
            else os.path.join(SAMPLES_BASE, sample_old or "")
        )
        new_path = (
            save_upload(new_file, "new.zip")
            if new_file
            else os.path.join(SAMPLES_BASE, sample_new or "")
        )

        if not (
            old_path
            and new_path
            and os.path.exists(old_path)
            and os.path.exists(new_path)
        ):
            raise ValueError("Missing or invalid input ZIPs")

        record_progress(run_id, "queued", 0)

        reports_base = await generate_reports_for_update(
            simulated=False, v1_zip=old_path, v2_zip=new_path, run_id=run_id
        )

        record_progress(run_id, "completed", 100)

        return {"reports_base": reports_base, "run_id": run_id, "ai_ready": True}

    except Exception as e:
        logger.exception("Manual analysis failed")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------
# AI ANALYSIS (unchanged)
# --------------------------------------------------------
@router.post("/ai_analyze")
async def ai_analyze():
    try:
        v1_dir = "/app/reports/current_run/notepad_v1_update/reports"
        v2_dir = "/app/reports/current_run/notepad_v2_update/reports"

        if not os.path.exists(os.path.join(v1_dir, "deep_analysis.json")):
            raise FileNotFoundError("v1 deep_analysis.json missing")

        if not os.path.exists(os.path.join(v2_dir, "deep_analysis.json")):
            raise FileNotFoundError("v2 deep_analysis.json missing")

        result = await run_llm_analysis(v1_dir, v2_dir)

        return JSONResponse(
            { "md": result["md"], "ai_report_path": result["ai_report_path"] },
            status_code=200
        )

    except Exception as e:
        logger.exception("AI analysis failed")
        raise HTTPException(status_code=500, detail=str(e))



# --------------------------------------------------------
# SERVE REPORTS (unchanged)
# --------------------------------------------------------

@router.get("/reports/{report_dir:path}")
async def get_report(report_dir: str):
    """
    Serve reports under REPORTS_BASE.

    Accepts either:
      - a directory path relative to REPORTS_BASE (e.g. current_run/notepad_v1_update/reports)
        -> If 'full_report.html' exists inside the directory, return that file.
        -> Else, if JSON files are present, return a JSON map of those files.
      - a file path relative to REPORTS_BASE (e.g. current_run/notepad_v1_update/reports/deep_analysis.json)
        -> Return that file directly with FileResponse.
    """
    abs_path = os.path.join(REPORTS_BASE, report_dir)

    # Normalize path to avoid path traversal (very basic safeguard)
    abs_path = os.path.normpath(abs_path)

    if not os.path.exists(abs_path):
        # If the request asked for a directory without trailing slash on some clients,
        # also try adding /reports suffix (legacy) - not strictly necessary but helps compatibility.
        raise HTTPException(status_code=404, detail="Report not found")

    # If the path points to a file, return it directly
    if os.path.isfile(abs_path):
        return FileResponse(abs_path)

    # If the path is a directory, prefer full_report.html if present
    html_path = os.path.join(abs_path, "full_report.html")
    if os.path.exists(html_path) and os.path.isfile(html_path):
        return FileResponse(html_path)

    # If no full_report.html, but json files exist, return them as JSON
    json_files = [f for f in os.listdir(abs_path) if f.lower().endswith(".json")]
    if json_files:
        return JSONResponse(
            {f: json.load(open(os.path.join(abs_path, f))) for f in json_files}
        )

    raise HTTPException(status_code=404, detail="No report data")

# --------------------------------------------------------
# PROGRESS API (unchanged)
# --------------------------------------------------------

@router.get("/progress/{run_id}")
async def get_progress(run_id: str):
    return JSONResponse(record_progress(run_id, only_get=True))
