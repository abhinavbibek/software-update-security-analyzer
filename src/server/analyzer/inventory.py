"""
inventory.py — helpers for managing file inventories
"""
import json, os

def load_inventory(path):
    if not os.path.exists(path):return []
    with open(path,"r",encoding="utf-8") as f:return json.load(f)

def save_inventory(path,data):
    with open(path,"w",encoding="utf-8") as f:json.dump(data,f,indent=2)
