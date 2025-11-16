"""
differ.py — compute diffs between two baseline inventories
"""
from pathlib import Path

def compare_inventories(old_list,new_list):
    old_files={i['path']:i for i in old_list}
    new_files={i['path']:i for i in new_list}
    added=[n for p,n in new_files.items() if p not in old_files]
    removed=[o for p,o in old_files.items() if p not in new_files]
    modified=[]
    for p in set(old_files)&set(new_files):
        if old_files[p]['sha256']!=new_files[p]['sha256']:
            modified.append({'path':p,'old':old_files[p],'new':new_files[p]})
    return {'added':added,'removed':removed,'modified':modified}
