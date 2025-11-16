"""
Unit test for static_pipeline.py

Ensures that:
 - baseline_inventory.json and deep_analysis.json are generated
 - HTML report exists
 - Returned lists are non-empty for sample inputs
"""
import os
import json
import pytest
from src.server.analyzer.static_pipeline import run_pipeline

SAMPLES_DIR = "samples"
REPORTS_DIR = "reports/test_static_pipeline"

@pytest.mark.order(1)
def test_run_pipeline_generates_reports(tmp_path):
    sample_zip = os.path.join(SAMPLES_DIR, "notepad_v1.zip")
    if not os.path.exists(sample_zip):
        pytest.skip("Sample notepad_v1.zip missing in samples/")
    out_dir = tmp_path / "out"
    result = run_pipeline(sample_zip, str(out_dir))
    reports_dir = result["reports_dir"]

    baseline = os.path.join(reports_dir, "baseline_inventory.json")
    deep = os.path.join(reports_dir, "deep_analysis.json")
    html = os.path.join(reports_dir, "full_report.html")

    assert os.path.exists(baseline), "baseline_inventory.json missing"
    assert os.path.exists(deep), "deep_analysis.json missing"
    assert os.path.exists(html), "full_report.html missing"

    with open(baseline) as f:
        data = json.load(f)
        assert isinstance(data, list)
        assert len(data) > 0, "baseline_inventory.json empty"

    with open(deep) as f:
        data = json.load(f)
        assert isinstance(data, list)
        # deep may be empty if no prioritized files, so only check type

    print(f"[TEST] Reports generated successfully at {reports_dir}")
