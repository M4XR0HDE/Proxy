import json
import os

def add_to_whitelist(domain, whitelist_path=None):
    domain = domain.strip()
    if not domain:
        print("No domain provided.")
        return
    # Always use the absolute path to whitelist.json in the proxy folder
    if whitelist_path is None:
        whitelist_path = os.path.join(os.path.dirname(__file__), 'whitelist.json')
    if not os.path.exists(whitelist_path):
        whitelist = []
    else:
        with open(whitelist_path) as f:
            try:
                whitelist = json.load(f)
            except Exception:
                whitelist = []
    if domain not in whitelist:
        whitelist.append(domain)
        with open(whitelist_path, 'w') as f:
            json.dump(whitelist, f, indent=4)
        print(f"Added {domain} to whitelist.")
    else:
        print(f"{domain} is already in the whitelist.")
