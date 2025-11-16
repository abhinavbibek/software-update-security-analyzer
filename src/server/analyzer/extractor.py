#extractor.py

import re, math, subprocess, os

ASCII_RE = re.compile(rb'[\x20-\x7E]{4,}')
UTF16LE_RE = re.compile(rb'(?:[\x20-\x7E]\x00){4,}')

def extract_strings_from_bytes(data:bytes):
    ascii=[m.decode('latin1') for m in ASCII_RE.findall(data)]
    utf16=[]
    for m in UTF16LE_RE.findall(data):
        try:utf16.append(m.decode('utf-16le'))
        except Exception:pass
    return ascii+utf16

def file_entropy_bytes(data:bytes):
    if not data:return 0.0
    freq=[0]*256
    for b in data:freq[b]+=1
    ent=0.0;ln=len(data)
    for c in freq:
        if c:p=c/ln;ent-=p*math.log2(p)
    return ent

def safe_mime(path):
    try:
        import magic
        return magic.from_file(path,mime=True)
    except Exception:
        ext=os.path.splitext(path)[1].lower()
        if ext in ('.exe','.dll'):return 'application/x-dosexec'
        if ext in ('.js','.py','.bat'):return 'text/plain'
        return 'application/octet-stream'

def run_cmd(cmd,timeout=8):
    try:
        out=subprocess.check_output(cmd,stderr=subprocess.DEVNULL,timeout=timeout)
        return out.decode(errors='ignore')
    except Exception:
        return ""
