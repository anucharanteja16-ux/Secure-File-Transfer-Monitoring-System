import json, html
from pathlib import Path
from datetime import datetime
from collections import Counter
BASE=Path(__file__).resolve().parent
def generate_report():
    records=[]; invalid=0
    p=BASE/'logs'/'transfers.jsonl'
    if p.exists():
        for line in p.read_text(encoding='utf-8').splitlines():
            try: records.append(json.loads(line))
            except ValueError: invalid+=1
    esc=lambda x:html.escape(str(x))
    counts=Counter(r['classification'] for r in records)
    rows=''.join('<tr>'+''.join('<td>'+esc(r.get(k,''))+'</td>' for k in ('timestamp','kind','classification','authorized','source','destination','destination_type','session_user'))+'</tr>' for r in records)
    alerts=''.join('<h3>'+esc(p.name)+'</h3><pre>'+esc(p.read_text(encoding='utf-8',errors='replace'))+'</pre>' for p in sorted((BASE/'alerts').glob('*.log')))
    out=BASE/'reports'/('audit_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f')+'.html'); out.parent.mkdir(exist_ok=True)
    out.write_text(f'''<!doctype html><meta charset="utf-8"><title>Transfer audit</title><style>body{{font:15px Arial;margin:32px;color:#183047}}table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border:1px solid #ccd;padding:8px;overflow-wrap:anywhere}}th{{background:#e7eef5}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}</style><h1>Secure File Transfer Audit</h1><p>Generated {datetime.now().isoformat()} | All recorded sessions</p><p>Transfers: {len(records)} | Unauthorized: {sum(not r['authorized'] for r in records)} | Classification: {esc(dict(counts))} | Invalid records: {invalid}</p><p>Hash correlation is inferential; session user is not actor identity. Local cloud folder events do not establish upload completion.</p><table><tr>{''.join('<th>'+k+'</th>' for k in ('Time','Event','Class','Allowed','Source','Destination','Type','Session user'))}</tr>{rows}</table><h2>Alert logs</h2>{alerts}''',encoding='utf-8')
    return out
