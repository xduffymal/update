"""Persist user-controlled experiment options and data-retention settings."""
import json
import sqlite3
import uuid
from datetime import datetime,timedelta,timezone
import lab_core as core

def get_settings():
    with core.connect() as c: rows=c.execute('SELECT key,value FROM system_settings').fetchall()
    return {r['key']:json.loads(r['value']) for r in rows}

def save_retention(days,user):
    if not 0<=days<=3650: raise ValueError('Choose 0 (disabled) or 1–3650 retention days.')
    with core.connect() as c: c.execute('INSERT OR REPLACE INTO system_settings VALUES(?,?)',('retention_days',json.dumps(days)))
    core.audit('set_retention_policy',user,{'days':days})

def apply_retention(user):
    days=get_settings().get('retention_days',0)
    if not days: raise ValueError('Retention is disabled.')
    cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
    backup=core.ROOT/'backups'/f'retention_{uuid.uuid4().hex}.db'; backup.parent.mkdir(parents=True,exist_ok=True)
    with core.connect() as c:
        ids=[r[0] for r in c.execute('SELECT id FROM email_scans WHERE created_at<?',(cutoff,))]
        with sqlite3.connect(backup) as snapshot: c.backup(snapshot)
        for scan in ids:
            for table in ['url_findings','attachment_findings','scan_findings','email_indicators','email_alerts','analyst_feedback']:
                c.execute(f'DELETE FROM {table} WHERE scan_id=?',(scan,))
            c.execute('DELETE FROM email_scans WHERE id=?',(scan,))
    core.audit('apply_retention',user,{'removed_scans':len(ids),'cutoff':cutoff,'recoverable_backup':str(backup.relative_to(core.ROOT))})
    return len(ids)
