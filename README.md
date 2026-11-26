# Secure File Transfer Monitoring System
Windows prototype | Python 3.10+ | Watchdog

## Setup
Extract into a NEW folder. Open it in VS Code. Run `python -m pip install -r requirements.txt`, then `python main.py`. Keep only one monitor instance running. Ctrl+C stops monitoring and generates an HTML audit. `python main.py report` generates another report. `python main.py approve monitored/example.txt` accepts a new integrity baseline; stop the monitor first and use only after review.

## Configuration
Edit config.json before startup. Desktop and OneDrive environment roots are discovered automatically. USB detection polls Windows removable drive types every five seconds; some USB disks report as fixed and require manual configuration. Add accessible local sync roots to cloud_folders and accessible UNC or mapped shares to network_folders. JSON example: `"network_folders": ["Z:/Shared"]`. Only monitor destinations you own or are authorized to monitor. Network notification support depends on server and driver. A folder containing the protected root is skipped to avoid overlapping watches. Bulk threshold defaults to five correlated outbound transfers in 60 seconds.

## Architecture
Watchdog observers -> event queue -> stable SHA-256 calculation -> current source index / recent deletion correlation -> authorization policy -> activity and alert logs -> HTML audit. Integrity baselines are separate from current content hashes. File classification uses name, extension and directory, not content. The session account and monitor PID are recorded, not the actor process. Actual actor attribution requires Windows auditing or endpoint telemetry outside this prototype.

## Testing on Windows
Keep monitor running in terminal 1; use terminal 2. Run the following with fresh test filenames and synthetic content only. Wait five seconds after creation and each transfer. Use a fresh destination name if it already exists.

```powershell
$desktop = [Environment]::GetFolderPath('Desktop')
New-Item -ItemType Directory -Force monitored/Finance
Set-Content monitored/secret_final.txt 'unique synthetic secret 1'
Set-Content monitored/notes_final.txt 'unique synthetic notes 2'
Set-Content monitored/Finance/report_final.txt 'unique synthetic report 3'
Start-Sleep 5
Copy-Item monitored/secret_final.txt $desktop
Copy-Item monitored/notes_final.txt $desktop
Move-Item monitored/Finance/report_final.txt $desktop
Start-Sleep 5
Add-Content monitored/secret_final.txt 'changed'
```
Expected: sensitive copy alert, normal copy authorized, confidential movement alert, integrity alert. For USB, insert a drive, wait for WATCH ACTIVE, then copy a fresh uniquely named test file. For cloud/network, configure an authorized test folder and restart; copy a fresh test file there. For bulk, create five uniquely named files with distinct content, wait for indexing, then copy them within 60 seconds. Test ignored filenames only in a disposable subfolder. Save screenshots of startup, alerts, USB watch, bulk alert, audit and integrity result. Do not fabricate screenshots.

## Outputs
logs/activity.log, logs/transfers.jsonl, logs/hash_baseline.json, logs/integrity_state.json; alerts/copy_alerts.log, movement_alerts.log, integrity_alerts.log, bulk_alerts.log (created when needed); reports/audit_*.html. Audit covers all structured transfers in the current project, not legacy activity lines.

## Limitations
Hash matches suggest but do not prove copy/move causation. Identical content can be ambiguous. Short-lived events, locked files, directory moves, missed notifications, disconnected destinations, renamed sensitivity labels and unobserved destinations can evade detection. No transfer blocking, upload confirmation, download attribution, or actual actor/process attribution. Local logs are not tamper-proof. External modification of existing matching content may be reported as potential copy. Bulk detection counts correlated events, not bytes. System-file exclusions are blind spots. Only one instance is supported. Windows runtime tests and screenshots remain to be performed.

## Viva
1. Why SHA-256? Content fingerprint and integrity comparison.
2. Copy vs move? A matching live source suggests copy; a recent deleted source suggests movement.
3. Why Watchdog? Cross-platform filesystem notifications, not actor attribution.
4. Why separate baseline and current index? Detect tampering while correlating current content.
5. What is DLP? Policies for identifying and reducing unauthorized data movement; this prototype alerts rather than blocks.
6. Future scope? Windows object-access auditing, durable sensitivity labels, signed centralized logs, cloud provider audit APIs and enterprise DLP enforcement.
