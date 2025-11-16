"""
scorer.py — simple heuristic risk scoring
"""
def compute_score(entropy, keyword_count, ioc_count, is_pe=False, has_cert=False):
    s=(entropy/8.0)*40.0
    s+=min(keyword_count*4.0,20.0)
    s+=min(ioc_count*6.0,24.0)
    if is_pe and not has_cert:s+=10.0
    return round(min(100.0,s),2)
