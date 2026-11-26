import json
from pathlib import Path
BASE = Path(__file__).resolve().parents[1]
def load_config():
    return json.loads((BASE / 'config.json').read_text(encoding='utf-8-sig'))
def classify_file(path):
    c = load_config()
    parts = str(path).replace('\\', '/').lower().split('/')
    name = parts[-1]
    if set(parts[:-1]) & {x.lower() for x in c['restricted_directories']}:
        return 'CONFIDENTIAL'
    if any(x.lower() in name for x in c['sensitive_keywords']) or any(name.endswith(x.lower()) for x in c['sensitive_extensions']):
        return 'SENSITIVE'
    return 'NORMAL'
def is_sensitive(path):
    return classify_file(path) != 'NORMAL'
