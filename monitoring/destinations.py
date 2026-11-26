import os, ctypes, string
from pathlib import Path
def removable_drives():
    if os.name != 'nt': return []
    return [f'{letter}:\\' for letter in string.ascii_uppercase if ctypes.windll.kernel32.GetDriveTypeW(f'{letter}:\\') == 2]
def destinations(config,desktop):
    result=[]
    if config.get('monitor_desktop'): result.append((desktop,'DESKTOP'))
    if config.get('monitor_onedrive'):
        for key in ('OneDrive','OneDriveConsumer','OneDriveCommercial'):
            if os.environ.get(key): result.append((os.environ[key],'CLOUD_FOLDER'))
    for key,kind in [('cloud_folders','CLOUD_FOLDER'),('network_folders','NETWORK_FOLDER')]:
        result.extend((os.path.expanduser(os.path.expandvars(p)),kind) for p in config.get(key,[]))
    if config.get('monitor_usb'): result.extend((p,'REMOVABLE_DRIVE') for p in removable_drives())
    return [(os.path.abspath(p),k) for p,k in result if os.path.isdir(p)]
