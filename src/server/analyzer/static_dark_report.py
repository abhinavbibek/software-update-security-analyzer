#!/usr/bin/env python3
"""
static_analyzer_dark_report.py

Two-phase static analyzer with dark-themed HTML report.

Usage:
python3 static_analyzer_dark_report.py --zip /path/to/update.zip --out /path/to/outdir [--analyze-all] [--workers N]
"""
import argparse
import os
import zipfile
import hashlib
import json
import re
import math
import subprocess
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.server.utils import record_progress


# Optional libs
try:
    import pefile
except Exception:
    pefile = None

try:
    import lief
except Exception:
    lief = None

try:
    import magic
except Exception:
    magic = None

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except Exception:
    x509 = None

# Optional cert validation libraries
try:
    from certvalidator import CertificateValidator, ValidationContext, errors as certv_errors
except Exception:
    CertificateValidator = None
    ValidationContext = None
    certv_errors = None

try:
    from oscrypto import trust_list as oscrypto_trust_list
except Exception:
    oscrypto_trust_list = None

# ---------- Config ----------
PRIORITIZED_EXTS = {'.exe', '.dll', '.msi', '.ps1', '.bat', '.js', '.jar', '.so', '.dylib', '.sh', '.py'}
SUSPICIOUS_KEYWORDS = [
    "Invoke-WebRequest","Invoke-Expression","IEX","DownloadFile","DownloadString",
    "powershell","curl","wget","eval(","base64","certutil","Add-Type","CreateObject",
    "Set-ExecutionPolicy","Mshta","ShellExecute","CreateProcess","VirtualAlloc","LoadLibrary",
    "GetProcAddress","Sleep","Start-Process","Process.Start","WScript.Shell","ActiveXObject",
    "RegOpenKey","RegSetValue","CreateRemoteThread","VirtualProtect","URLDownloadToFile"
]
URL_RE = re.compile(r'(https?://[^\s\'"<>]+)', re.IGNORECASE)
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', re.IGNORECASE)
ASCII_STR_RE = re.compile(rb'[\x20-\x7E]{4,}')
UTF16LE_STR_RE = re.compile(rb'(?:[\x20-\x7E]\x00){4,}')

SCORE_CONFIG = {
    "entropy_max": 40.0,
    "keyword_each": 4.0,
    "ioc_each": 6.0,
    "unsigned_pe_bonus": 10.0,
    "max_keyword_total": 20.0,
    "max_ioc_total": 24.0
}

# ---------- Utilities ----------
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def md5_file(path):
    m = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            m.update(chunk)
    return m.hexdigest()

def file_entropy_bytes(data: bytes):
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = 0.0
    ln = len(data)
    for c in freq:
        if c:
            p = c/ln
            ent -= p * math.log2(p)
    return ent

def extract_strings_from_bytes(data: bytes):
    ascii = [m.decode('latin1') for m in ASCII_STR_RE.findall(data)]
    utf16 = []
    for m in UTF16LE_STR_RE.findall(data):
        try:
            utf16.append(m.decode('utf-16le'))
        except Exception:
            pass
    return ascii + utf16

def safe_mime(path):
    if magic:
        try:
            return magic.from_file(path, mime=True)
        except Exception:
            pass
    ext = Path(path).suffix.lower()
    if ext in ('.exe', '.dll'): return 'application/x-dosexec'
    if ext in ('.msi',): return 'application/x-msi'
    if ext in ('.ps1', '.bat', '.sh'): return 'text/x-script'
    if ext in ('.js', '.vbs', '.py', '.pl'): return 'text/plain'
    return 'application/octet-stream'

def run_cmd(cmd, timeout=8):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode(errors='ignore')
    except Exception:
        return None

def compute_score(entropy, keyword_count, ioc_count, is_pe, has_cert):
    s = 0.0
    s += min(SCORE_CONFIG["entropy_max"], (entropy/8.0) * SCORE_CONFIG["entropy_max"])
    s += min(SCORE_CONFIG["max_keyword_total"], keyword_count * SCORE_CONFIG["keyword_each"])
    s += min(SCORE_CONFIG["max_ioc_total"], ioc_count * SCORE_CONFIG["ioc_each"])
    if is_pe and not has_cert:
        s += SCORE_CONFIG["unsigned_pe_bonus"]
    return round(min(100.0, s), 2)

# ---------- PE/LIEF parsing ----------
def parse_pe_pefile_bytes(data: bytes):
    result = {}
    if not pefile:
        result['note'] = 'pefile not installed'
        return result
    try:
        pe = pefile.PE(data=data, fast_load=True)
        try:
            pe.parse_data_directories()
        except Exception:
            pass
        result['timestamp'] = getattr(pe.FILE_HEADER, 'TimeDateStamp', None)
        result['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, 'OPTIONAL_HEADER') else None

        imports = []
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
            try:
                mod = entry.dll.decode(errors='ignore')
            except Exception:
                mod = str(entry.dll)
            funcs = []
            for imp in entry.imports:
                try:
                    funcs.append(imp.name.decode(errors='ignore') if imp.name else str(imp.ordinal))
                except Exception:
                    funcs.append(str(getattr(imp, 'ordinal', '')))
            imports.append({'module': mod, 'functions': funcs})
        result['imports'] = imports

        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    exports.append(exp.name.decode(errors='ignore') if exp.name else str(exp.ordinal))
                except Exception:
                    exports.append(str(getattr(exp, 'ordinal', '')))
        result['exports'] = exports

        secs = []
        for s in pe.sections:
            try:
                name = s.Name.decode(errors='ignore').rstrip('\x00')
            except Exception:
                name = str(s.Name)
            secs.append({
                'name': name,
                'virtual_size': getattr(s, 'Misc_VirtualSize', None),
                'raw_size': getattr(s, 'SizeOfRawData', None),
                'entropy': round(file_entropy_bytes(s.get_data()), 4)
            })
        result['sections'] = secs
    except Exception as e:
        result['pe_parse_error'] = str(e)
    return result

# Cert verification helper: best-effort using certvalidator + oscrypto if available
def _build_oscrypto_trust_roots():
    """
    Try to obtain a list of trust root certificates from oscrypto.trust_list.
    Return a list of cryptography x509 objects or None if not possible.
    """
    if not oscrypto_trust_list:
        return None
    try:
        # oscrypto.trust_list exposes functions depending on platform.
        # get_list() returns list of oscrypto.asymmetric.Certificate objects on some versions.
        roots = []
        if hasattr(oscrypto_trust_list, "get_windows_trust_list"):
            try:
                items = oscrypto_trust_list.get_windows_trust_list()
            except Exception:
                items = None
        else:
            try:
                items = oscrypto_trust_list.get_list()
            except Exception:
                items = None

        if not items:
            return None

        for it in items:
            try:
                # items may be bytes of DER or oscrypto objects; try to get DER bytes
                der = None
                if isinstance(it, bytes):
                    der = it
                else:
                    # try object attribute
                    if hasattr(it, "dump"):
                        try:
                            der = it.dump()
                        except Exception:
                            der = None
                    elif hasattr(it, "as_der"):
                        try:
                            der = it.as_der()
                        except Exception:
                            der = None
                if der and x509:
                    cert = x509.load_der_x509_certificate(der, default_backend())
                    roots.append(cert)
            except Exception:
                # skip items we can't parse
                continue
        if roots:
            return roots
    except Exception:
        return None
    return None

def verify_cert_trust_chain(der_bytes):
    """
    Best-effort chain validation:
      - Uses certvalidator + oscrypto trust_list if available.
      - Returns dict: { 'trusted': True/False/None, 'reason': str }
    """
    if not CertificateValidator or not ValidationContext:
        return {'trusted': None, 'reason': 'certvalidator not installed'}

    if not x509:
        return {'trusted': None, 'reason': 'cryptography not installed'}

    try:
        target_cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    except Exception as e:
        return {'trusted': None, 'reason': f'unable to parse DER cert: {e}'}

    # Build trust roots if possible
    trust_roots = None
    try:
        trust_roots = _build_oscrypto_trust_roots()
    except Exception:
        trust_roots = None

    try:
        validation_context = ValidationContext(trust_roots=trust_roots) if ValidationContext else None
        validator = CertificateValidator(target_cert, validation_context=validation_context)
        # validate() raises on errors; we catch them and return False
        validator.validate_usage(set(['digital_signature']))
        return {'trusted': True, 'reason': ''}
    except Exception as e:
        # certvalidator-specific PathValidationError gives details via certv_errors.PathValidationError if available
        reason = str(e)
        return {'trusted': False, 'reason': reason}



def parse_with_lief(path):
    """
    Extended LIEF + pefile hybrid parser.
    Extracts signature/cert info (Authenticode) using both LIEF and pefile fallback.
    Performs trust verification when possible.
    """
    result = {}
    # Try primary LIEF parsing
    if not lief:
        result['note'] = 'lief not installed'
        return result
    try:
        binary = lief.parse(path)
        if not binary:
            result['lief_parse_note'] = 'lief.parse returned falsy'
            return result
        has_sig = getattr(binary, "has_signature", False)
        result["has_signature"] = bool(has_sig)
        certs = []

        # --- Primary LIEF signatures ---
        if has_sig:
            for sig in getattr(binary, "signatures", []):
                try:
                    raw = bytes(sig.content)
                    if x509:
                        try:
                            cert = x509.load_der_x509_certificate(raw, default_backend())
                            trustinfo = verify_cert_trust_chain(raw)
                            certs.append({
                                'subject': cert.subject.rfc4514_string(),
                                'issuer': cert.issuer.rfc4514_string(),
                                'not_before': cert.not_valid_before.isoformat(),
                                'not_after': cert.not_valid_after.isoformat(),
                                'trusted': trustinfo.get('trusted'),
                                'reason': trustinfo.get('reason', '')
                            })
                        except Exception as e:
                            certs.append({'note': f'cryptography parse failed: {e}'})
                    else:
                        certs.append({'note': 'cryptography not installed'})
                except Exception as e:
                    certs.append({'note': f'failed parsing signature blob: {e}'})

        # --- Fallback: Extract from WIN_CERTIFICATE (pefile) ---
        if not certs and pefile:
            try:
                pe = pefile.PE(path, fast_load=True)
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                    for entry in pe.DIRECTORY_ENTRY_SECURITY:
                        data = entry.struct
                        offset = data.VirtualAddress
                        size = data.Size
                        if size > 0:
                            pe_data = pe.write()[offset+8:offset+size]  # skip WIN_CERTIFICATE header
                            try:
                                cert = x509.load_der_x509_certificate(pe_data, default_backend())
                                trustinfo = verify_cert_trust_chain(pe_data)
                                certs.append({
                                    'subject': cert.subject.rfc4514_string(),
                                    'issuer': cert.issuer.rfc4514_string(),
                                    'not_before': cert.not_valid_before.isoformat(),
                                    'not_after': cert.not_valid_after.isoformat(),
                                    'trusted': trustinfo.get('trusted'),
                                    'reason': trustinfo.get('reason', '')
                                })
                            except Exception as e:
                                certs.append({'note': f'fallback parse failed: {e}'})
            except Exception as e:
                result["pefile_fallback_error"] = str(e)

        result["certs"] = certs

        # --- Section entropy details ---
        secs = []
        try:
            for s in binary.sections:
                contents = bytes(s.content) if hasattr(s, 'content') else b''
                secs.append({
                    'name': getattr(s, 'name', None),
                    'size': getattr(s, 'size', None),
                    'virtual_size': getattr(s, 'virtual_size', None),
                    'entropy': round(file_entropy_bytes(contents), 4)
                })
            result['sections_lief'] = secs
        except Exception:
            pass

    except Exception as e:
        result['lief_parse_error'] = str(e)

    return result

SUSPICIOUS_API_KEYWORDS = {
    'network': ['connect', 'send', 'recv', 'WSAStartup', 'InternetOpen', 'InternetReadFile', 'URLDownloadToFile'],
    'process': ['CreateProcess', 'ShellExecute', 'system', 'exec', 'CreateRemoteThread'],
    'registry': ['RegOpenKey', 'RegSetValue', 'RegCreateKey'],
    'crypto': ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'RtlEncryptMemory']
}

def analyze_imported_apis(imports):
    findings = {'network': [], 'process': [], 'registry': [], 'crypto': []}
    for imp in imports:
        for func in imp.get('functions', []):
            fname = func.lower()
            for cat, kws in SUSPICIOUS_API_KEYWORDS.items():
                for kw in kws:
                    if kw.lower() in fname:
                        findings[cat].append(func)
    for k in findings:
        findings[k] = sorted(set(findings[k]))
    return findings

# ---------- Analysis workers ----------
def lightweight_analysis_file(abs_path, rel_path):
    entry = {
        'path': rel_path,
        'sha256': None,
        'md5': None,
        'size': None,
        'mime': None,
        'entropy': None,
        'strings_count': 0,
        'sample_strings': [],
        'ioc': {'urls': [], 'domains': [], 'ips': []},
        'suspicious_keywords': [],
        'notes': []
    }
    try:
        with open(abs_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        entry['notes'].append(f'unreadable: {e}')
        return entry

    entry['sha256'] = sha256_file(abs_path)
    entry['md5'] = md5_file(abs_path)
    entry['size'] = os.path.getsize(abs_path)
    entry['mime'] = safe_mime(abs_path)
    ent = file_entropy_bytes(data)
    entry['entropy'] = round(ent, 4)

    strings = extract_strings_from_bytes(data)
    entry['strings_count'] = len(strings)
    entry['sample_strings'] = strings[:30]

    all_text = "\n".join(strings)
    entry['ioc']['urls'] = list(set(URL_RE.findall(all_text)))
    entry['ioc']['domains'] = list(set(DOMAIN_RE.findall(all_text)))
    entry['ioc']['ips'] = list(set(IP_RE.findall(all_text)))

    low = all_text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in low:
            entry['suspicious_keywords'].append(kw)

    return entry

def deep_analysis_file(abs_path, rel_path, lw_entry, run_external_tools=True):
    d = {
        'path': rel_path,
        'sha256': lw_entry.get('sha256'),
        'md5': lw_entry.get('md5'),
        'size': lw_entry.get('size'),
        'mime': lw_entry.get('mime'),
        'entropy': lw_entry.get('entropy'),
        'strings_count': lw_entry.get('strings_count'),
        'ioc': lw_entry.get('ioc'),
        'suspicious_keywords': lw_entry.get('suspicious_keywords'),
        'file_info': {},
        'strings_file': None,
        'exiftool': None,
        'packer_heuristic': {},
        'pe': {},
        'lief': {},
        'imported_api_findings': {},
        'ioc_additional': {'urls': [], 'domains': [], 'ips': []},
        'analysis_notes': []
    }

    if run_external_tools:
        try:
            fi = run_cmd(['file', '--brief', '--mime-type', abs_path]) or ''
            d['file_info']['file_cmd'] = fi.strip()
        except Exception:
            pass
        try:
            s_out = run_cmd(['strings', '-n', '4', abs_path])
            d['strings_file'] = s_out.splitlines()[:200] if s_out else []
        except Exception:
            pass
        try:
            ex = run_cmd(['exiftool', abs_path])
            d['exiftool'] = ex.splitlines() if ex else None
        except Exception:
            pass

    try:
        ent = float(d['entropy']) if d['entropy'] is not None else 0.0
        d['packer_heuristic']['entropy'] = ent
        d['packer_heuristic']['maybe_packed'] = ent > 7.0 or (ent > 6.5 and ent < 7.5)
    except Exception:
        pass

    ext = Path(abs_path).suffix.lower()
    raw = None
    try:
        with open(abs_path, 'rb') as f:
            raw = f.read()
    except Exception:
        d['analysis_notes'].append('unable to read bytes for deep parse')

    if ext in ('.exe', '.dll', '.msi') or (raw and raw[:2] == b'MZ'):
        try:
            pe_info = parse_pe_pefile_bytes(raw or b'')
            d['pe'] = pe_info
        except Exception as e:
            d['analysis_notes'].append('pefile error: ' + str(e))
        try:
            lief_info = parse_with_lief(abs_path)
            d['lief'] = lief_info
        except Exception as e:
            d['analysis_notes'].append('lief error: ' + str(e))
        try:
            api_findings = analyze_imported_apis(d['pe'].get('imports', []))
            d['imported_api_findings'] = api_findings
        except Exception:
            pass

    try:
        strings_to_scan = []
        if d.get('strings_file'):
            strings_to_scan = [s.decode('latin1') if isinstance(s, bytes) else s for s in d['strings_file']]
        else:
            strings_to_scan = extract_strings_from_bytes(raw or b'')
        joined = "\n".join(strings_to_scan)
        new_urls = list(set(URL_RE.findall(joined)))
        new_domains = list(set(DOMAIN_RE.findall(joined)))
        new_ips = list(set(IP_RE.findall(joined)))
        for u in new_urls:
            if u not in d['ioc']['urls']:
                d['ioc_additional']['urls'].append(u)
        for dn in new_domains:
            if dn not in d['ioc']['domains']:
                d['ioc_additional']['domains'].append(dn)
        for ip in new_ips:
            if ip not in d['ioc']['ips']:
                d['ioc_additional']['ips'].append(ip)
    except Exception:
        pass

    try:
        keyword_count = len(d.get('suspicious_keywords', []))
        ioc_count = len(d['ioc']['urls']) + len(d['ioc']['domains']) + len(d['ioc']['ips']) \
                    + len(d['ioc_additional']['urls']) + len(d['ioc_additional']['domains']) + len(d['ioc_additional']['ips'])
        is_pe = bool(d.get('pe'))
        has_cert = bool(d.get('lief', {}).get('has_signature')) or bool(d.get('lief', {}).get('certs'))
        d['deep_risk_score'] = compute_score(float(d.get('entropy') or 0.0), keyword_count, ioc_count, is_pe, has_cert)
    except Exception:
        d['deep_risk_score'] = 0.0

    summary_lines = []
    try:
        summary_lines.append(f"Size: {d.get('size')}, Entropy: {d.get('entropy')}")
        if d.get('pe'):
            summary_lines.append("PE parsed")
            api = d.get('imported_api_findings', {})
            for cat, items in api.items():
                if items:
                    summary_lines.append(f"{cat} APIs: {', '.join(items[:6])}")
        if d.get('ioc_additional', {}).get('domains'):
            summary_lines.append("Additional domains: " + ", ".join(d['ioc_additional']['domains'][:5]))
        if d.get('ioc_additional', {}).get('urls'):
            summary_lines.append("Additional urls: " + ", ".join(d['ioc_additional']['urls'][:3]))
    except Exception:
        pass
    d['human_summary'] = " | ".join(summary_lines)
    return d

# ---------- HTML Generator (dark dashboard) ----------
def risk_color(score):
    try:
        s = float(score)
    except Exception:
        return '#777'
    if s >= 70:
        return '#ff4d4f'  # red
    if s >= 40:
        return '#ffa940'  # amber
    return '#73d13d'      # green

def cert_trust_color(trust_val):
    # trust_val: True/False/None
    if trust_val is True:
        return '#52c41a'  # green
    if trust_val is False:
        return '#ff4d4f'  # red
    return '#ffa940'      # amber (not verified / unknown)

def html_escape(s):
    return (str(s) if s is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def create_html_report(baseline, deep, out_html, run_id):
    """
    Generate the HTML report file at out_html.
    Progress is emitted using the run_id derived from the out_html path:
        run_id = os.path.dirname(os.path.dirname(out_html))
    """
    # Determine top-level run directory to use as run_id for progress updates
    # out_html is expected to be: <out_dir>/reports/full_report.html
    #run_id = os.path.dirname(os.path.dirname(out_html))

    # Notify frontend that HTML generation started

    overall_top = sorted(deep, key=lambda e: e.get('deep_risk_score', 0.0), reverse=True)[:8]
    gen_time = datetime.utcnow().isoformat() + "Z"
    total_files = len(baseline)
    total_deep = len(deep)
    # aggregate global iocs
    global_urls = set()
    global_domains = set()
    global_ips = set()
    for b in baseline:
        for u in b.get('ioc', {}).get('urls', []):
            global_urls.add(u)
        for d in b.get('ioc', {}).get('domains', []):
            global_domains.add(d)
        for ip in b.get('ioc', {}).get('ips', []):
            global_ips.add(ip)

    css = """
    body { background:#0b1020; color:#d6e4ff; font-family:Inter,Segoe UI,Roboto,Helvetica,Arial; margin:0; padding:20px;}
    .container{max-width:1300px;margin:0 auto;}
    .header{display:flex;align-items:center;gap:16px;margin-bottom:18px}
    .logo{width:56px;height:56px;border-radius:8px;background:linear-gradient(135deg,#0f1724,#12203a);display:flex;align-items:center;justify-content:center}
    .title{font-size:20px;font-weight:700}
    .meta{color:#9fb0ff;font-size:13px}
    .banner{display:flex;gap:12px;margin:18px 0}
    .card{background:#071029;border:1px solid #16263b;padding:12px;border-radius:10px;flex:1}
    .card h3{margin:0 0 8px 0;color:#bcd0ff}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{padding:8px 10px;border-bottom:1px solid #122034;font-size:13px}
    th{background:rgba(255,255,255,0.02);text-align:left;color:#9fb0ff}
    tr:hover td{background:rgba(255,255,255,0.01)}
    .small{font-size:12px;color:#9fb0ff}
    .badge{display:inline-block;padding:4px 8px;border-radius:999px;font-weight:600;font-size:12px}
    .ioc-list{max-width:420px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .section-title{margin-top:22px;margin-bottom:6px;color:#a8c0ff;font-weight:700}
    .file-block{background:#061027;padding:10px;border-radius:8px;border:1px solid #14243a;margin-bottom:10px}
    .pre{background:#041526;padding:8px;border-radius:6px;color:#cfe8ff;font-family:monospace;font-size:12px;overflow:auto;max-height:160px}
    .table-thin td{font-size:12px;padding:6px 8px}
    .risk-pill{padding:6px 10px;border-radius:999px;color:#0b1020;font-weight:700}
    .cert-pill{padding:4px 8px;border-radius:8px;color:#021124;font-weight:700;display:inline-block}
    """

    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    html.append("<title>Static Analysis — Dark Analyst Dashboard</title>")
    html.append(f"<style>{css}</style></head><body>")
    html.append("<div class='container'>")
    # header
    html.append("<div class='header'><div class='logo'><svg width='30' height='30' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'><rect x='2' y='2' width='20' height='20' rx='4' fill='#0ea5e9'/><path d='M6 12h12M12 6v12' stroke='#021124' stroke-width='1.5' stroke-linecap='round'/></svg></div>")
    html.append("<div><div class='title'>Static Analysis — Dark Analyst Dashboard</div>")
    html.append(f"<div class='meta'>Generated: {gen_time} • Files scanned: {total_files} • Deep-scanned: {total_deep}</div></div></div>")

    # banner with top risky
    html.append("<div class='banner'>")
    html.append("<div class='card'><h3>Top risky deep-scanned files</h3>")
    if overall_top:
        html.append("<ol class='small'>")
        for e in overall_top:
            score = e.get('deep_risk_score', 0.0)
            html.append(f"<li style='margin-bottom:6px'><span style='color:{risk_color(score)};font-weight:700'>{score}</span> — {html_escape(e.get('path'))} <span class='small'>| {html_escape(e.get('human_summary',''))}</span></li>")
        html.append("</ol>")
    else:
        html.append("<div class='small'>No deep-scanned files returned high risk.</div>")
    html.append("</div>")

    # global IOCs card
    html.append("<div class='card'><h3>Global IOCs</h3>")
    html.append(f"<div class='small'>Unique URLs: {len(global_urls)} • Domains: {len(global_domains)} • IPs: {len(global_ips)}</div>")
    html.append("<div style='margin-top:8px'><details style='color:#9fb0ff'><summary class='small'>Show first 50 sample domains/urls</summary>")

    html.append("<div class='pre' style='white-space:pre-wrap; line-height:1.4;'>")
    if global_domains:
        html.append("<b>First 50 Domains:</b><br>" + html_escape('\n'.join(list(global_domains)[:80])) + "<br><br>")
    if global_urls:
        html.append("<b>First 50 URLs:</b><br>" + html_escape('\n'.join(list(global_urls)[:80])) + "<br><br>")
    if global_ips:
        html.append("<b>First 50 IPs:</b><br>" + html_escape('\n'.join(list(global_ips)[:80])) + "<br><br>")
    html.append("</div></details></div></div></div>")

    # Baseline table (general files)
    html.append("<div class='section-title'>Baseline — All files (filename • entropy • suspicious IOCs)</div>")
    html.append("<div class='file-block'>")
    html.append("<table class='table-thin'><thead><tr><th>Filename</th><th>Entropy</th><th>Suspicious IOCs (domains/urls/ip)</th></tr></thead><tbody>")
    # show top 200 baseline entries (or all if small)
    for b in baseline[:500]:
        path = b.get('path')
        ent = b.get('entropy')
        iocs = []
        if b.get('ioc', {}).get('domains'): iocs.extend(b['ioc']['domains'][:2])
        if b.get('ioc', {}).get('urls'): iocs.extend(b['ioc']['urls'][:2])
        if b.get('ioc', {}).get('ips'): iocs.extend(b['ioc']['ips'][:2])
        iocs_s = ", ".join(iocs) if iocs else ""
        html.append(f"<tr><td style='width:50%'>{html_escape(path)}</td><td style='width:10%' class='small'>{html_escape(ent)}</td><td class='ioc-list'>{html_escape(iocs_s)}</td></tr>")
    html.append("</tbody></table></div>")

    # Deep analysis table
    html.append("<div class='section-title'>Deep Analysis — Prioritized files</div>")
    if not deep:
        html.append("<div class='card'><div class='small'>No prioritized files were deep-scanned.</div></div>")
    else:
        # For each deep result produce a detailed block
        for d in sorted(deep, key=lambda e: e.get('deep_risk_score',0.0), reverse=True):
            score = d.get('deep_risk_score', 0.0)
            color = risk_color(score)
            html.append("<div class='file-block'>")
            # header row with basic file info
            html.append("<div style='display:flex;justify-content:space-between;align-items:center'>")
            html.append(f"<div><b style='font-size:14px'>{html_escape(d.get('path'))}</b><div class='small'>{html_escape(d.get('mime',''))} • size: {d.get('size')} • strings: {d.get('strings_count')}</div></div>")
            html.append(f"<div style='text-align:right'><span class='risk-pill' style='background:{color};'>{score}</span><div class='small' style='margin-top:6px'>MD5: {html_escape(d.get('md5',''))}<br>SHA256: {html_escape(d.get('sha256',''))}</div></div>")
            html.append("</div>")

            # two-column table: left = parsed info, right = IOCs & summary
            html.append("<div style='display:grid;grid-template-columns:1fr 420px;gap:12px;margin-top:8px'>")
            # left column: details
            html.append("<div>")
            # file cmd, exiftool summary
            html.append("<table><tbody>")
            # file_info
            file_cmd = d.get('file_info',{}).get('file_cmd')
            if file_cmd:
                html.append(f"<tr><th style='width:180px'>file</th><td class='small'>{html_escape(file_cmd)}</td></tr>")
            if d.get('exiftool'):
                exs = "\\n".join(d.get('exiftool')[:10])
                html.append(f"<tr><th>exiftool</th><td class='pre small'>{html_escape(exs)}</td></tr>")
            # entropy/packer
            html.append(f"<tr><th>Entropy</th><td class='small'>{html_escape(d.get('entropy'))} • maybe_packed: {d.get('packer_heuristic',{}).get('maybe_packed')}</td></tr>")
            # PE details
            if d.get('pe'):
                pe = d['pe']
                html.append(f"<tr><th>Entry point</th><td class='small'>{html_escape(pe.get('entry_point'))}</td></tr>")
                # sections
                secs = pe.get('sections', [])
                if secs:
                    secs_s = ", ".join([s.get('name','') + f"({s.get('entropy')})" for s in secs[:6]])
                    html.append(f"<tr><th>Sections</th><td class='small'>{html_escape(secs_s)}</td></tr>")
                # imports summary
                imports = pe.get('imports', [])
                if imports:
                    imp_s = ", ".join([imp.get('module') for imp in imports[:6]])
                    html.append(f"<tr><th>Imports</th><td class='small'>{html_escape(imp_s)}</td></tr>")
                exports = pe.get('exports', [])
                if exports:
                    html.append(f"<tr><th>Exports</th><td class='small'>{html_escape(', '.join(exports[:8]))}</td></tr>")
            # lief/cert
            if d.get('lief'):
                lieb = d['lief']
                if 'has_signature' in lieb:
                    html.append(f"<tr><th>Signed</th><td class='small'>{html_escape(str(lieb.get('has_signature')))}</td></tr>")
                if lieb.get('certs'):
                    # show expanded certificate info with trust status
                    cert0 = lieb['certs'][0]
                    subj = cert0.get('subject') if isinstance(cert0, dict) else None
                    issuer = cert0.get('issuer') if isinstance(cert0, dict) else None
                    nb = cert0.get('not_before') if isinstance(cert0, dict) else None
                    na = cert0.get('not_after') if isinstance(cert0, dict) else None
                    trusted = cert0.get('trusted') if isinstance(cert0, dict) else None
                    reason = cert0.get('reason','') if isinstance(cert0, dict) else ''
                    trust_status = "Not Verified"
                    if trusted is True:
                        trust_status = "Trusted"
                    elif trusted is False:
                        trust_status = "Untrusted"
                    pill_color = cert_trust_color(trusted)
                    html.append("<tr><th>Certificate</th><td class='small'>")
                    html.append(f"Subject: {html_escape(subj)}<br>Issuer: {html_escape(issuer)}<br>")
                    html.append(f"Validity: {html_escape(nb)} → {html_escape(na)}<br>")
                    html.append(f"Authenticity: <span class='cert-pill' style='background:{pill_color};'>{html_escape(trust_status)}</span>")
                    if reason:
                        html.append(f"<div class='small' style='margin-top:6px;color:#9fb0ff'>Reason: {html_escape(reason)}</div>")
                    html.append("</td></tr>")
            html.append("</tbody></table>")

            # imported API findings
            if d.get('imported_api_findings'):
                html.append("<div style='margin-top:8px'><b class='small'>API categories</b>")
                api = d.get('imported_api_findings', {})
                for cat, items in api.items():
                    if items:
                        html.append(f"<div class='small' style='margin-top:4px'><b>{cat}:</b> {html_escape(', '.join(items[:10]))}</div>")
                html.append("</div>")
            html.append("</div>")  # left column end

            # right column: IOCs and summary
            html.append("<div>")
            # IOCs
            html.append("<div class='small'><b>IOCs (baseline)</b></div>")
            html.append("<div class='small ioc-list'>" + html_escape(", ".join(d.get('ioc', {}).get('domains', [])[:10])) + "</div>")
            html.append("<div class='small' style='margin-top:8px'><b>IOCs (discovered in deep scan)</b></div>")
            html.append("<div class='small ioc-list'>" + html_escape(", ".join(d.get('ioc_additional', {}).get('domains', [])[:10])) + "</div>")
            html.append("<div style='margin-top:8px'><b class='small'>Human summary</b>")
            html.append("<div class='small pre'>" + html_escape(d.get('human_summary','')) + "</div></div>")
            # suspicious keywords
            if d.get('suspicious_keywords'):
                html.append("<div style='margin-top:8px'><b class='small'>Suspicious keywords</b>")
                html.append("<div class='small'>" + html_escape(", ".join(d.get('suspicious_keywords')[:10])) + "</div></div>")
            # raw strings sample toggle
            if d.get('strings_file'):
                html.append("<details style='margin-top:8px' class='small'><summary>Show first 200 strings</summary>")
                sample = "\\n".join([s.decode('latin1') if isinstance(s, bytes) else s for s in d.get('strings_file')[:200]])
                html.append("<div class='pre'>" + html_escape(sample) + "</div></details>")
            html.append("</div>")  # right column end

            html.append("</div>")  # grid end
            # notes
            if d.get('analysis_notes'):
                html.append("<div style='margin-top:8px' class='small'><b>Notes:</b> " + html_escape("; ".join(map(str, d.get('analysis_notes'))[:200])) + "</div>")
            html.append("</div>")  # file-block end

    # footer
    html.append("<div style='margin-top:22px;font-size:12px;color:#8fa8ff'>Report generated by static_analyzer — summary time: " + gen_time + "</div>")
    html.append("</div></body></html>")

    # Finish: write HTML file
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("\n".join(html))





# ---------- Pipeline orchestration (same as earlier) ----------
def run_pipeline(zip_path, out_dir, analyze_all=False, workers=4, run_id=None):
    run_id = run_id or out_dir
    ensure_dir(out_dir)
    extract_dir = os.path.join(out_dir, "extracted")
    reports_dir = os.path.join(out_dir, "reports")
    ensure_dir(extract_dir)
    ensure_dir(reports_dir)

    record_progress(run_id, "Extracting ZIP...", 10)
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(extract_dir)

    files = []
    for root, dirs, fnames in os.walk(extract_dir):
        for f in fnames:
            absf = os.path.join(root, f)
            relf = os.path.relpath(absf, extract_dir)
            files.append((absf, relf))

    # lightweight phase
    baseline_results = []
    deep_candidates = []
    print(f"[+] Lightweight scan of {len(files)} files (workers={workers})...")
    #record_progress(run_id, "Lightweight scan started...", 30)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(lightweight_analysis_file, absf, relf): (absf, relf) for absf, relf in files}
        for fut in as_completed(futures):
            absf, relf = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                res = {'path': relf, 'notes': [f'error during lightweight: {exc}']}
            baseline_results.append(res)
            if len(baseline_results) % 50 == 0:
                pct = min(60, 30 + int((len(baseline_results) / len(files)) * 30))
                #record_progress(run_id, f"Lightweight scan: {len(baseline_results)}/{len(files)} files", pct)
            ext = Path(relf).suffix.lower()
            if analyze_all or ext in PRIORITIZED_EXTS:
                deep_candidates.append((absf, relf, res))


    
    # save baseline — ONLY prioritized extension files
    prioritized_baseline = [
        entry for entry in baseline_results
        if Path(entry.get("path", "")).suffix.lower() in PRIORITIZED_EXTS
    ]

    with open(os.path.join(reports_dir, "baseline_inventory.json"), "w", encoding='utf-8') as f:
        json.dump(prioritized_baseline, f, indent=2)


    # order deep candidates
    ext_priority = {e: i for i, e in enumerate(sorted(list(PRIORITIZED_EXTS)))}
    deep_candidates_sorted = sorted(deep_candidates, key=lambda x: (ext_priority.get(Path(x[1]).suffix.lower(), 999), -float(x[2].get('entropy') or 0.0)))

    # deep phase
        # deep phase
    deep_results = []
    # (optional) remove or keep the print; you can keep for local debug but it's not required
    # print(f"[+] Deep scanning {len(deep_candidates_sorted)} prioritized files...")
    #record_progress(run_id, "Deep analysis started...", 60)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(deep_analysis_file, absf, relf, lw_entry): (absf, relf) for absf, relf, lw_entry in deep_candidates_sorted}
        total_deep = len(deep_candidates_sorted) or 1
        completed = 0
        for fut in as_completed(futures):
            absf, relf = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                res = {'path': relf, 'analysis_notes': [f'error during deep analysis: {exc}'], 'deep_risk_score': 0.0}
            deep_results.append(res)
            completed += 1

            # Emit progress every 5-10 files (tunable)
            if completed % 10 == 0 or completed == total_deep:
                pct = min(85, 60 + int((completed / total_deep) * 25))
                record_progress(run_id, f"Deep scan: {completed}/{total_deep} files", pct)


    # save deep results
    with open(os.path.join(reports_dir, "deep_analysis.json"), "w", encoding='utf-8') as f:
        json.dump(deep_results, f, indent=2)

    # create HTML report (dark dashboard)
    create_html_report(baseline_results, deep_results, os.path.join(reports_dir, "full_report.html"), run_id)

    print("[+] Reports written to:", reports_dir)
    return {'reports_dir': reports_dir}

def main():
    parser = argparse.ArgumentParser(description="Static Analyzer (dark dashboard)")
    parser.add_argument("--zip", required=True, help="Path to update ZIP file")
    parser.add_argument("--out", required=True, help="Output base directory")
    parser.add_argument("--analyze-all", action='store_true', help="Deep analyze all files (not just prioritized)")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers")
    args = parser.parse_args()

    print("[*] Starting static analyzer (dark report)")
    start = datetime.utcnow()
    results = run_pipeline(args.zip, args.out, analyze_all=args.analyze_all, workers=args.workers)
    end = datetime.utcnow()
    print(f"[*] Done in {(end - start).total_seconds():.1f}s. Reports: {results['reports_dir']}")

if __name__ == "__main__":
    main()
