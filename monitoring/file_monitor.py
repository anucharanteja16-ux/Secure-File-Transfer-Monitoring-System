import os
import time
import logging
import getpass
import hashlib
import subprocess
from queue import Queue, Empty
from collections import deque
from monitoring.destinations import destinations
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from security.integrity import verify_integrity, move_baseline, load_data, BASELINE_FILE
from security.sensitive_files import classify_file, load_config
from security.authorization import check_authorization

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
ALERT_DIR = os.path.join(BASE_DIR, 'alerts')
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ALERT_DIR, exist_ok=True)
logging.basicConfig(filename=os.path.join(LOG_DIR, 'activity.log'), level=logging.INFO,
                    format='%(asctime)s | %(message)s', encoding='utf-8')
MATCH_WINDOW = 60
CHECK_DELAY = 3


def normalize(path):
    return os.path.normcase(os.path.abspath(path))


def is_inside(path, folder):
    try:
        return os.path.commonpath([normalize(path), normalize(folder)]) == normalize(folder)
    except ValueError:
        return False


def get_desktop_folder():
    if os.name == 'nt':
        try:
            path = subprocess.check_output(['powershell.exe', '-NoProfile', '-Command',
                "[Environment]::GetFolderPath('Desktop')"], text=True, timeout=10).strip()
            if os.path.isdir(path):
                return path
        except (OSError, subprocess.SubprocessError):
            pass
    return os.path.join(os.path.expanduser('~'), 'Desktop')


def calculate_hash(path):
    before = os.stat(path)
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            digest.update(chunk)
    after = os.stat(path)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError('File is changing')
    return digest.hexdigest()


class FileMonitor(FileSystemEventHandler):
    def __init__(self, folder):
        super().__init__()
        self.folder = os.path.abspath(folder)
        self.desktop = get_desktop_folder()
        self.config = load_config()
        self.ignored = {x.lower() for x in self.config.get('ignored_filenames', ['desktop.ini', 'thumbs.db'])}
        self.events = Queue()
        self.checks = {}
        self.deleted = {}
        self.created = {}
        self.index = {}
        self.recent = {}
        self.targets = {}
        self.bulk = deque()
        self.last_bulk = -1e12

    def destination_type(self, path):
        matches = [(len(root), kind) for root, kind in self.targets.items() if is_inside(path, root)]
        return max(matches)[1] if matches else "OTHER"

    def ignored_file(self, path):
        return os.path.basename(path).lower() in self.ignored

    def log(self, message, warning=False):
        print(message)
        (logging.warning if warning else logging.info)(message)

    def activity(self, kind, path):
        self.log(f'Event: {kind} | Classification: {classify_file(path)} | Session user: {getpass.getuser()} | File: {path}')

    def transfer(self, kind, source, dest):
        key = (normalize(source), normalize(dest), kind)
        now = time.monotonic()
        if now - self.recent.get(key, -100) < 5:
            return
        self.recent[key] = now
        allowed, classification = check_authorization(source, dest)
        status = 'AUTHORIZED' if allowed else 'UNAUTHORIZED'
        message = f'{status} {kind} | Classification: {classification} | Session user: {getpass.getuser()} | From: {source} | To: {dest}'
        message += f' | Destination: {self.destination_type(dest)} | Actor process: UNKNOWN | Monitor PID: {os.getpid()}'
        self.log(message, not allowed)
        if not is_inside(dest, self.folder):
            now = time.monotonic()
            self.bulk.append(now)
            window = self.config.get('bulk_window_seconds',60)
            while self.bulk and now-self.bulk[0]>window: self.bulk.popleft()
            if len(self.bulk)>=self.config.get('bulk_count',5) and now-self.last_bulk>=window:
                self.last_bulk=now
                bulk_msg=f'BULK TRANSFER ALERT | {len(self.bulk)} correlated transfers within {window}s'
                self.log(bulk_msg,True)
                if self.config.get('enable_security_alerts',True):
                    with open(os.path.join(ALERT_DIR,'bulk_alerts.log'),'a',encoding='utf-8') as f: f.write(time.strftime('%Y-%m-%d %H:%M:%S')+' | '+bulk_msg+'\n')
        with open(os.path.join(LOG_DIR,'transfers.jsonl'),'a',encoding='utf-8') as f:
            f.write(json.dumps(dict(timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),kind=kind,source=source,destination=dest,classification=classification,authorized=allowed,session_user=getpass.getuser(),actor_process=None,destination_type=self.destination_type(dest)))+'\n')
        if not allowed and self.config.get('enable_security_alerts', True):
            print('[SECURITY ALERT]')
            name = 'copy_alerts.log' if kind == 'POTENTIAL FILE COPY' else 'movement_alerts.log'
            with open(os.path.join(ALERT_DIR, name), 'a', encoding='utf-8') as f:
                f.write(time.strftime('%Y-%m-%d %H:%M:%S') + ' | ' + message + '\n')

    def baseline_key(self, path):
        return next((p for p in load_data(BASELINE_FILE) if normalize(p) == normalize(path)), path)

    def index_file(self, path, digest):
        self.index[normalize(path)] = (path, digest)
        if self.config.get('enable_integrity_check', True):
            verify_integrity(path)

    def initialize(self):
        for root, _, files in os.walk(self.folder):
            for name in files:
                path = os.path.join(root, name)
                if self.ignored_file(path):
                    continue
                try:
                    self.index_file(path, calculate_hash(path))
                except OSError as e:
                    self.log(f'[INDEX WARNING] {path}: {e}', True)

    def schedule(self, path, creation=False):
        key = normalize(path)
        old = self.checks.get(key)
        self.checks[key] = [path, time.monotonic() + CHECK_DELAY, creation or bool(old and old[2]), 0]

    def remember_deleted(self, path):
        key = normalize(path)
        item = self.index.pop(key, None)
        if item:
            self.deleted[key] = (item[0], item[1], time.monotonic())

    def match(self):
        now = time.monotonic()
        self.deleted = {k:v for k,v in self.deleted.items() if now-v[2] <= MATCH_WINDOW}
        self.created = {k:v for k,v in self.created.items() if now-v[2] <= MATCH_WINDOW}
        self.recent = {k:v for k,v in self.recent.items() if now-v <= MATCH_WINDOW}
        for key, (dest, digest, stamp) in list(self.created.items()):
            if not os.path.isfile(dest):
                self.created.pop(key, None)
                continue
            removed = [(k,v) for k,v in self.deleted.items() if v[1] == digest and k != key and not os.path.exists(v[0])]
            live = [(p,h) for k,(p,h) in self.index.items() if k != key and h == digest and os.path.isfile(p)]
            try:
                if calculate_hash(dest) != digest:
                    self.created.pop(key, None)
                    continue
                live = [(p,h) for p,h in live if calculate_hash(p) == digest]
            except OSError:
                continue
            if len(removed) == 1 and not live:
                oldkey, (source, _, _) = removed[0]
                self.transfer('FILE MOVEMENT', source, dest)
                if is_inside(dest, self.folder):
                    if self.config.get('enable_integrity_check', True):
                        move_baseline(self.baseline_key(source), dest)
                    self.index_file(dest, digest)
                self.deleted.pop(oldkey, None)
                self.created.pop(key, None)
            elif not is_inside(dest, self.folder) and not removed and len(live) == 1:
                self.transfer('POTENTIAL FILE COPY', live[0][0], dest)
                self.created.pop(key, None)
            elif len(removed) + len(live) > 1:
                self.log(f'[AMBIGUOUS HASH MATCH] {dest} | Source not established', True)
                self.created.pop(key, None)

    def process_checks(self):
        now = time.monotonic()
        for key, info in list(self.checks.items()):
            path, due, creation, retries = info
            if now < due:
                continue
            if not os.path.isfile(path):
                self.checks.pop(key, None)
                continue
            try:
                digest = calculate_hash(path)
                if creation:
                    self.created[key] = (path, digest, time.monotonic())
                if is_inside(path, self.folder):
                    # Correlate internal moves before creating a new baseline.
                    self.match()
                    self.index_file(path, digest)
                self.checks.pop(key, None)
            except OSError as e:
                if retries >= 9:
                    self.log(f'[FILE CHECK ERROR] {path}: {e}', True)
                    self.checks.pop(key, None)
                else:
                    info[1] = now + 1
                    info[3] += 1
        self.match()

    def on_any_event(self, event):
        if event.is_directory or event.event_type not in ('created','modified','deleted','moved'):
            return
        src = os.path.abspath(event.src_path)
        dest = os.path.abspath(event.dest_path) if event.event_type == 'moved' else None
        self.events.put((event.event_type, src, dest))

    def handle(self, kind, path, dest):
        protected = is_inside(path, self.folder)
        if kind == 'moved':
            # Treat ignored-to-visible and visible-to-ignored renames separately.
            if self.ignored_file(path):
                if not self.ignored_file(dest):
                    self.handle('created', dest, None)
                return
            if self.ignored_file(dest):
                self.handle('deleted', path, None)
                return
        elif self.ignored_file(path):
            return
        key = normalize(path)
        if kind == 'created':
            self.activity('FILE CREATED' if protected else 'DESTINATION FILE CREATED', path)
            self.schedule(path, True)
        elif kind == 'modified':
            if protected and os.path.isfile(path):
                self.activity('FILE MODIFIED', path)
                self.schedule(path)
            elif os.path.isfile(path):
                self.schedule(path, True)
        elif kind == 'deleted':
            self.checks.pop(key, None)
            self.created.pop(key, None)
            if protected:
                self.activity('FILE DELETED', path)
                self.remember_deleted(path)
        elif kind == 'moved':
            self.checks.pop(key, None)
            self.created.pop(key, None)
            new_protected = is_inside(dest, self.folder)
            if protected:
                self.index.pop(key, None)
                self.transfer('FILE MOVEMENT', path, dest)
                if new_protected:
                    if self.config.get('enable_integrity_check', True):
                        move_baseline(self.baseline_key(path), dest)
                    self.schedule(dest)
            elif new_protected or self.destination_type(dest) != "OTHER":
                self.schedule(dest, True)


def start_monitoring(folder_path):
    os.makedirs(folder_path, exist_ok=True)
    handler = FileMonitor(folder_path)
    observer = Observer()
    observer.schedule(handler, handler.folder, recursive=True)
    watches = {}
    def refresh():
        candidates = sorted(destinations(handler.config,handler.desktop),key=lambda x:len(x[0]))
        desired = {}
        handler.targets = dict(candidates)
        for path,kind in candidates:
            if is_inside(path,handler.folder) or is_inside(handler.folder,path):
                continue
            if not any(is_inside(path,root) for root in desired): desired[path]=kind
        for path in list(watches):
            if path not in desired:
                observer.unschedule(watches.pop(path)); handler.log('[WATCH REMOVED] '+path)
        for path in desired:
            if path not in watches:
                try:
                    watches[path]=observer.schedule(handler,path,recursive=True)
                    handler.log('[WATCH ACTIVE] '+desired[path]+' | '+path)
                except OSError as e: handler.log('[WATCH ERROR] '+str(e),True)
    observer.start()
    try:
        print('SECURE FILE TRANSFER MONITORING SYSTEM - FINAL')
        print('Protected folder:',handler.folder)
        refresh(); handler.initialize()
        print('READY - Press Ctrl+C to stop')
        next_refresh=time.monotonic()+5
        while True:
            try: handler.handle(*handler.events.get(timeout=.25))
            except Empty: pass
            handler.process_checks()
            if time.monotonic()>=next_refresh:
                refresh(); next_refresh=time.monotonic()+5
    except KeyboardInterrupt: print('Stopping monitoring...')
    finally:
        observer.stop(); observer.join()
        from reporting import generate_report
        print('Audit report:',generate_report())
