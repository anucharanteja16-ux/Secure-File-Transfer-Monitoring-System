import hashlib
import json
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title='Secure File Transfer Monitor', page_icon='🛡️', layout='wide')
config = json.loads(Path(__file__).with_name('config.example.json').read_text(encoding='utf-8-sig'))

def classify(path):
    parts = path.replace('\\', '/').lower().split('/')
    name = parts[-1]
    if set(parts[:-1]) & {x.lower() for x in config['restricted_directories']}:
        return 'CONFIDENTIAL'
    if any(x.lower() in name for x in config['sensitive_keywords']) or any(name.endswith(x.lower()) for x in config['sensitive_extensions']):
        return 'SENSITIVE'
    return 'NORMAL'

st.title('🛡️ Secure File Transfer Monitoring System')
st.info('Interactive demonstration. Actual Windows filesystem monitoring runs separately using main.py. No live connection to your computer.')
if 'events' not in st.session_state:
    st.session_state.events = []
page = st.sidebar.radio('Navigation', ['Overview', 'Transfer simulator', 'Integrity verification', 'Audit viewer'])
if page == 'Transfer simulator':
    st.header('File transfer simulation')
    path = st.text_input('Synthetic source path', 'monitored/Finance/report.txt')
    dest = st.selectbox('Destination', ['Protected folder', 'Simulated USB', 'Cloud folder', 'Network folder', 'Desktop'])
    kind = st.selectbox('Transfer type', ['Potential copy', 'Movement'])
    count = st.number_input('Number of simulated transfers in one window', 1, 100, 1)
    if st.button('Evaluate transfer', disabled=not bool(path.strip())):
        label = classify(path)
        allowed = dest == 'Protected folder' or (label == 'NORMAL' and config['allow_normal_file_transfer'])
        for i in range(count):
            st.session_state.events.append({'source': path, 'destination_type': dest, 'kind': kind, 'classification': label, 'authorized': allowed})
        (st.success if allowed else st.error)(f'{"AUTHORIZED" if allowed else "UNAUTHORIZED"} | {label} | {kind}')
        if dest != 'Protected folder' and count >= config.get('bulk_count', 5):
            st.warning(f'BULK TRANSFER ALERT (simulated): {count} transfers in a {config.get("bulk_window_seconds",60)} second window')
    st.caption('Policy mirrors the default project rules. Batch simulation assumes all events occur in one window; it is not live event correlation.')
elif page == 'Integrity verification':
    st.header('SHA-256 integrity verification')
    a = st.file_uploader('Original synthetic test file', key='original')
    b = st.file_uploader('File to compare (optional)', key='comparison')
    if a is not None:
        h = hashlib.sha256(a.getvalue()).hexdigest()
        st.code(h)
        if b is not None:
            other = hashlib.sha256(b.getvalue()).hexdigest()
            st.code(other)
            if h == other: st.success('INTEGRITY OK — matching hashes')
            else: st.error('INTEGRITY ALERT — hashes differ')
    st.caption('Use synthetic files only. Uploaded bytes are processed by the hosted server; this does not update local baselines.')
else:
    st.header('Security analytics' if page == 'Overview' else 'Audit viewer')
    records = st.session_state.events
    if page == 'Audit viewer':
        upload = st.file_uploader('Optional sanitized transfers.jsonl', type=['jsonl'])
        if upload is not None:
            try:
                records = [json.loads(line) for line in upload.getvalue().decode('utf-8-sig').splitlines() if line.strip()]
                if not all(isinstance(r, dict) and isinstance(r.get('authorized'), bool) and isinstance(r.get('classification'), str) for r in records):
                    raise ValueError('Expected classification and boolean authorized fields')
            except (ValueError, UnicodeError) as e:
                st.error(f'Invalid audit data: {e}'); st.stop()
            st.caption('Source: uploaded audit records, not live monitoring.')
        else: st.caption('Source: simulated events in this session.')
    else: st.caption('Source: simulated events in this session.')
    total = len(records); allowed = sum(r.get('authorized') is True for r in records)
    for col, title, value in zip(st.columns(3), ['Total transfers','Authorized','Unauthorized'], [total, allowed, total-allowed]):
        col.metric(title, value)
    if records:
        df = pd.DataFrame(records)
        st.bar_chart(df['classification'].value_counts())
        st.dataframe(df, use_container_width=True)
        st.download_button('Download CSV report', df.to_csv(index=False), 'transfer_report.csv', 'text/csv')
    else: st.info('No records yet. Use the transfer simulator to generate demonstration events.')
    if st.button('Clear simulated session records'):
        st.session_state.events = []; st.rerun()
