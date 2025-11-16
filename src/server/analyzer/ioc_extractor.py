#ioc_extractor.py
import re

URL_RE=re.compile(r'(https?://[^\s\'"<>]+)',re.I)
DOMAIN_RE=re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b',re.I)
IP_RE=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SUSPICIOUS_KEYWORDS=[ "Invoke-WebRequest","powershell","curl","wget","eval(","base64","certutil",
    "CreateProcess","VirtualAlloc","LoadLibrary","RegSetValue","URLDownloadToFile" ]

def extract_iocs(strings):
    text="\n".join(strings)
    ioc={
        'urls':list(set(URL_RE.findall(text))),
        'domains':list(set(DOMAIN_RE.findall(text))),
        'ips':list(set(IP_RE.findall(text))),
    }
    low=text.lower();susp=[]
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in low:susp.append(kw)
    return ioc,susp
