#!/usr/bin/env python3
# src/cli.py
"""
CLI entrypoint for VersionDiff Sentinel (robust orchestrator).
Usage:
  python src/cli.py --old <old_zip> --new <new_zip> --out <out_dir>
"""
from pathlib import Path
import argparse, tempfile, shutil, json, sys, os, math, hashlib, re, csv
from datetime import datetime

# Ensure /app (container root) is in Python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.server.analyzer.extractor import extract_to_dir
from src.server.analyzer.inventory import build_inventory
from src.server.analyzer.differ import compute_diff
from src.server.analyzer.ioc_extractor import extract_iocs
# NOTE: reporter.generate_report signature changed — wrapper expects (old_zip, new_zip, out_dir)
from src.server.analyzer.reporter import generate_report


# scorer might exist; fallback to internal scoring if import fails
try:
    from src.server.analyzer.scorer import score_analysis as external_score_analysis
    HAVE_EXTERNAL_SCORER = True
except Exception:
    HAVE_EXTERNAL_SCORER = False

# Try to use pefile for deeper PE extraction if available
try:
    import pefile
    HAVE_PEFILE = True
except Exception:
    HAVE_PEFILE = False

RE_URL = re.compile(r'https?://[^\s\'"<>]+', re.I)
RE_DOMAIN = re.compile(r'\b([A-Za-z0-9.-]+\.[A-Za-z]{2,6})\b')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

SUSPICIOUS_KEYWORDS = [
    "Invoke-WebRequest","Invoke-Expression","FromBase64String","System.Net.WebClient",
    "curl","wget","powershell","eval","CreateRemoteThread","LoadLibrary","VirtualAlloc",
    "DownloadFile","WebClient","WinHttp","Invoke-Command"
]

def sha256_bytes(data: bytes):
    h = hashlib.sha256(); h.update(data); return h.hexdigest()

def entropy_bytes(data: bytes):
    if not data: return 0.0
    from collections import Counter
    cnt = Counter(data)
    L = len(data)
    e = 0.0
    for v in cnt.values():
        p = v / L
        e -= p * math.log2(p)
    return round(e,4)

def extract_strings(data: bytes, min_len=4, max_count=200):
    res = []
    cur = []
    for b in data:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                res.append(''.join(cur))
            cur = []
        if len(res) >= max_count:
            break
    if len(cur) >= min_len and len(res) < max_count:
        res.append(''.join(cur))
    return res

def analyze_pe(path: Path):
    data = path.read_bytes()
    out = {"sha256": sha256_bytes(data), "size": path.stat().st_size, "entropy": entropy_bytes(data), "strings": extract_strings(data,4,400), "imports": [], "exports": [], "certificate": None}
    if HAVE_PEFILE:
        try:
            pe = pefile.PE(str(path), fast_load=True)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, bytes) else str(entry.dll)
                    names = []
                    for imp in entry.imports:
                        if imp.name:
                            names.append(imp.name.decode(errors='ignore'))
                    out['imports'].append({"dll": dll, "names": names})
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                out['exports'] = [ (s.name.decode(errors='ignore') if s.name else "") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols ]
            # basic certificate presence detection (not full parsing)
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                    out['certificate'] = {"present": True}
            except Exception:
                out['certificate'] = None
        except Exception as e:
            out['pe_error'] = str(e)
    return out

def analyze_text(path: Path):
    data = path.read_bytes()
    strings = extract_strings(data, 4, 500)
    urls = RE_URL.findall(" ".join(strings[:400]))
    domains = RE_DOMAIN.findall(" ".join(strings[:400]))
    ips = RE_IP.findall(" ".join(strings[:400]))
    found_kw = []
    for kw in SUSPICIOUS_KEYWORDS:
        for s in strings[:200]:
            if kw.lower() in s.lower():
                found_kw.append(kw)
                break
    return {
        "sha256": sha256_bytes(data),
        "size": path.stat().st_size,
        "entropy": entropy_bytes(data),
        "strings": strings[:200],
        "suspicious_keywords": sorted(list(set(found_kw))),
        "iocs": list(dict.fromkeys(urls + domains + ips))
    }

def score_record(rec):
    # simple scoring to produce LOW/MEDIUM/HIGH
    score = 0
    reasons = []
    ent = rec.get("entropy") or 0.0
    if ent > 7.5: score += 3; reasons.append("very_high_entropy")
    elif ent > 6.5: score += 2; reasons.append("high_entropy")
    elif ent > 5.5: score += 1; reasons.append("moderate_entropy")
    if rec.get("certificate") is None and rec.get("type") == "pe":
        score += 2; reasons.append("unsigned_pe")
    sk = rec.get("suspicious_keywords") or []
    if sk:
        score += 2 * len(sk); reasons.append("suspicious_keywords")
    iocs = rec.get("iocs") or []
    if iocs:
        score += 2 * len(iocs); reasons.append("iocs")
    if score >= 6: level = "HIGH"
    elif score >= 3: level = "MEDIUM"
    elif score > 0: level = "LOW"
    else: level = "INFO"
    return score, level, reasons

def analyze(old_archive: str, new_archive: str, out_dir: str):
    old_archive = Path(old_archive)
    new_archive = Path(new_archive)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp = Path(tempfile.mkdtemp(prefix="vds-"))
    try:
        old_dir = tmp / "old"; new_dir = tmp / "new"
        old_dir.mkdir(); new_dir.mkdir()
        extract_to_dir(old_archive, old_dir)
        extract_to_dir(new_archive, new_dir)

        inv_old = build_inventory(old_dir)
        inv_new = build_inventory(new_dir)

        diff = compute_diff(inv_old, inv_new)

        analysis = []
        aggregate_iocs = {"urls": [], "domains": [], "ips": []}

        # process both added and modified
        for status_name, lst in (("added", diff.get("added", [])), ("modified", diff.get("modified", []))):
            for rel in lst:
                rec = {"path": rel, "status": status_name}
                fpath = (new_dir / rel) if status_name in ("added","modified") else (old_dir / rel)
                if not fpath.exists():
                    rec["error"] = "file missing after extraction"
                    analysis.append(rec); continue
                ext = fpath.suffix.lower()
                try:
                    if ext in (".exe",".dll",".sys",".ocx"):
                        rec["type"] = "pe"
                        pe = analyze_pe(fpath)
                        rec.update(pe)
                    elif ext in (".ps1",".bat",".sh",".js",".vbs",".psm1",".py"):
                        rec["type"] = "script"
                        txt = analyze_text(fpath)
                        rec.update(txt)
                    else:
                        rec["type"] = "other"
                        txt = analyze_text(fpath)
                        rec.update(txt)
                    # compute iocs aggregated
                    for i in rec.get("iocs", []):
                        if RE_URL.match(i): aggregate_iocs["urls"].append(i)
                        elif RE_IP.match(i): aggregate_iocs["ips"].append(i)
                        else: aggregate_iocs["domains"].append(i)
                    rec["score"], rec["level"], rec["reasons"] = score_record(rec)
                except Exception as e:
                    rec["analysis_error"] = str(e)
                analysis.append(rec)

        overall = max((r.get("score",0) for r in analysis), default=0)

        report = {
            "generated": datetime.utcnow().isoformat()+"Z",
            "release": {"old": old_archive.name, "new": new_archive.name},
            "diff": diff,
            "files": analysis,
            "iocs": aggregate_iocs,
            "scores": {"overall_score": overall}
        }

        # Use the new reporter wrapper: it expects (old_zip_path, new_zip_path, out_dir)
        try:
            reports_base = generate_report(str(old_archive), str(new_archive), str(out_dir))
            combined_path = Path(reports_base) / "combined_report.json"
            # If combined exists, return it; otherwise return the reports base
            if combined_path.exists():
                return str(combined_path)
            return str(reports_base)
        except Exception as e:
            # fallback: if generate_report not matching expected signature or fails, try legacy call
            try:
                generate_report(diff, {f['path']: f for f in analysis}, {"overall_score": overall}, out_dir)
                return str(out_dir / "report.json")
            except Exception:
                raise

    finally:
        try:
            shutil.rmtree(str(tmp))
        except Exception:
            pass

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", required=True)
    parser.add_argument("--new", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        print(analyze(args.old, args.new, args.out))
        return 0
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        return 2




if __name__ == "__main__":
    raise SystemExit(main())
