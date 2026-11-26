import os, json, hashlib, logging
from pathlib import Path
from datetime import datetime
BASE = Path(__file__).resolve().parents[1]
LOG = BASE / 'logs'; ALERT = BASE / 'alerts'
LOG.mkdir(exist_ok=True); ALERT.mkdir(exist_ok=True)
BASELINE_FILE = LOG / 'hash_baseline.json'; STATE_FILE = LOG / 'integrity_state.json'
def calculate_hash(path):
    h = hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(65536),b''): h.update(chunk)
    return h.hexdigest()
def load_data(path):
    try: return json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError: return {}
def save_data(path,data):
    p = Path(path); tmp = p.with_suffix('.tmp'); tmp.write_text(json.dumps(data,indent=2),encoding='utf-8'); os.replace(tmp,p)
def record_baseline(path,force=False):
    p=os.path.abspath(path); data=load_data(BASELINE_FILE)
    if force or p not in data:
        data[p]=calculate_hash(p); save_data(BASELINE_FILE,data); print('[BASELINE SAVED]',p)
    return data[p]
def verify_integrity(path):
    p=os.path.abspath(path); data=load_data(BASELINE_FILE); state=load_data(STATE_FILE)
    if p not in data: record_baseline(p); return True
    digest=calculate_hash(p)
    if digest==data[p]:
        if p in state: state.pop(p); save_data(STATE_FILE,state)
        return True
    if state.get(p)!=digest:
        msg=f'INTEGRITY ALERT | {p} | expected={data[p]} | actual={digest}'
        print(msg); logging.warning(msg)
        from security.sensitive_files import load_config
        if load_config().get('enable_security_alerts',True):
            with (ALERT/'integrity_alerts.log').open('a',encoding='utf-8') as f: f.write(f'{datetime.now().isoformat()} | {msg}\n')
        state[p]=digest; save_data(STATE_FILE,state)
    return False
def move_baseline(old,new):
    data=load_data(BASELINE_FILE); old=os.path.abspath(old); new=os.path.abspath(new)
    if old in data:
        if new not in data: data[new]=data[old]
        data.pop(old); save_data(BASELINE_FILE,data)
def approve_current_version(path):
    record_baseline(path,True); state=load_data(STATE_FILE); state.pop(os.path.abspath(path),None); save_data(STATE_FILE,state)
