"""
Unit test for reporter.py

Ensures that reporter wrapper correctly triggers pipeline
and creates both version reports.
"""
import os
import json
import pytest
from src.server.reporter import generate_reports_for_update

@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_generate_reports_creates_dual_reports(tmp_path):
    reports_dir = tmp_path / "reports"
    os.makedirs(reports_dir, exist_ok=True)

    # Simulate two test zips
    samples_dir = "samples"
    v1_zip = os.path.join(samples_dir, "notepad_v1.zip")
    v2_zip = os.path.join(samples_dir, "notepad_v2.zip")
    if not (os.path.exists(v1_zip) and os.path.exists(v2_zip)):
        pytest.skip("Required sample zips missing.")

    out_dir = await generate_reports_for_update(
        simulated=False, v1_zip=v1_zip, v2_zip=v2_zip, run_id="test_run"
    )

    assert os.path.exists(out_dir), "Report base dir missing"
    v1_dir = os.path.join(out_dir, "v1_update")
    v2_dir = os.path.join(out_dir, "v2_update")

    for sub in [v1_dir, v2_dir]:
        assert os.path.exists(os.path.join(sub, "baseline_inventory.json"))
        assert os.path.exists(os.path.join(sub, "deep_analysis.json"))
        assert os.path.exists(os.path.join(sub, "full_report.html"))

    meta_path = os.path.join(out_dir, "run_metadata.json")
    assert os.path.exists(meta_path), "run_metadata.json missing"

    with open(meta_path) as f:
        meta = json.load(f)
        assert "v1_report" in meta and "v2_report" in meta

    print(f"[TEST] Reporter successfully generated dual reports in {out_dir}")
