import argparse
from pathlib import Path
BASE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser(description='Secure File Transfer Monitoring System')
    p.add_argument('action',nargs='?',default='monitor',choices=['monitor','report','approve'])
    p.add_argument('path',nargs='?'); a=p.parse_args()
    if a.action=='report':
        from reporting import generate_report
        print(generate_report())
    elif a.action=='approve':
        from security.integrity import approve_current_version
        if not a.path: p.error('approve requires a file path')
        approve_current_version(a.path)
    else:
        from monitoring.file_monitor import start_monitoring
        start_monitoring(str(BASE/'monitored'))
if __name__=='__main__': main()
