from pathlib import Path
import csv,hashlib,sqlite3
root=Path(__file__).resolve().parent
count=0
with (root/'FILES_SHA256.csv').open(encoding='utf-8-sig',newline='') as f:
    for row in csv.DictReader(f):
        path=root/row['path']
        with path.open('rb') as source:actual=hashlib.file_digest(source,'sha256').hexdigest()
        if actual!=row['sha256']:raise SystemExit('Changed/missing file: '+row['path'])
        count+=1
for name in ['cyber_threat.db','cyber_threat-Mal.db']:
    with sqlite3.connect((root/name).as_uri()+'?mode=ro',uri=True) as c:
        if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise SystemExit('Database integrity failure: '+name)
print('Verified',count,'file hashes and both SQLite databases.')
