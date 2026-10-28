"""Allowlisted public datasets with publisher checksums and real label provenance."""
import csv
import hashlib
import json
import random
import threading
import time
import uuid
from pathlib import Path
import requests
import truststore
import lab_core as core
truststore.inject_into_ssl()

RECORD='8339691'
SOURCES={
    'enron':{'file':'Enron.csv','name':'Enron legitimate subset — Champa et al. curated corpus','label':'0','md5':'10489e0fdcc8af6fe62135c689367d40'},
    'nazario':{'file':'Nazario.csv','name':'Nazario phishing corpus — Champa et al. curated corpus','label':'1','md5':'4022d055bb7cf8602f30f768f652e91e'},
}
_collection_locks={}
_collection_guard=threading.Lock()

def publish_download(temporary,path):
    for attempt in range(6):
        try: temporary.replace(path); return
        except PermissionError:
            if attempt==5: raise ValueError('The downloaded dataset is temporarily locked by Windows. Wait a moment and collect again; your saved datasets are unchanged.')
            time.sleep(.1*2**attempt)

def collect_public(key,limit=100,intended='training',seed=42):
    lock_key=(str(core.ROOT.resolve()),key)
    with _collection_guard: lock=_collection_locks.setdefault(lock_key,threading.Lock())
    with lock: return _collect_public(key,limit,intended,seed)

def _collect_public(key,limit,intended,seed):
    if key not in SOURCES: raise ValueError('Choose a supported public source.')
    if not 10<=limit<=5000: raise ValueError('Choose 10–5000 records per source.')
    cfg=SOURCES[key]; url=f'https://zenodo.org/api/records/{RECORD}/files/{cfg["file"]}/content'
    cache=core.ROOT/'data/raw/public_sources'; cache.mkdir(parents=True,exist_ok=True)
    path=cache/cfg['file']
    if not path.exists():
        info=requests.get(f'https://zenodo.org/api/records/{RECORD}',timeout=30); info.raise_for_status()
        if info.json()['metadata'].get('license',{}).get('id')!='cc-by-4.0': raise ValueError('Publisher license changed. Review permitted use before importing.')
        temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.partial')
        try:
            size=0
            with requests.get(url,stream=True,timeout=(30,120)) as response:
                response.raise_for_status()
                with temporary.open('wb') as out:
                    for chunk in response.iter_content(1024*1024):
                        size+=len(chunk)
                        if size>96*1024*1024: raise ValueError('Public dataset exceeds collection size limit.')
                        out.write(chunk)
            with temporary.open('rb') as f: downloaded_digest=hashlib.file_digest(f,'md5').hexdigest()
            if downloaded_digest!=cfg['md5']: raise ValueError('Publisher dataset checksum mismatch; source was not imported.')
            publish_download(temporary,path)
        finally:
            try: temporary.unlink(missing_ok=True)
            except PermissionError: pass  # Preserve the original error if Windows still holds the temporary file.
    with path.open('rb') as f: digest=hashlib.file_digest(f,'md5').hexdigest()
    if digest!=cfg['md5']: raise ValueError('Publisher dataset checksum mismatch; source was not imported.')
    csv.field_size_limit(16*1024*1024)
    excluded=set(); excluded_urls=set()
    if intended=='validation':
        for split in core.splits():
            used=core.read_csv(core.artifact(split['train']))+core.read_csv(core.artifact(split['test']))
            excluded.update(map(core.fingerprint,used))
            excluded_urls.update(u.lower() for r in used for u in core.extract_urls(r.get('urls','')+' '+r.get('body','')))
    selected=[]; seen=0; rng=random.Random(seed)
    with path.open(encoding='utf-8-sig',newline='') as f:
        for r in csv.DictReader(f):
            if str(r.get('label','')).strip()!=cfg['label']: continue
            text=r.get('body') or r.get('text') or r.get('email') or ''
            if not text.strip(): continue
            if core.fingerprint({'subject':r.get('subject',''),'body':text}) in excluded: continue
            if any(u.lower() in excluded_urls for u in core.extract_urls(text)): continue
            seen+=1
            if len(selected)<limit: selected.append(r)
            else:
                i=rng.randrange(seen)
                if i<limit: selected[i]=r
    if not selected: raise ValueError('Source contains no records with the expected label/schema.')
    notes=f'CC BY 4.0. Attribution: Champa, Rabbi & Zibran; Phishing Email Curated Datasets, DOI 10.5281/zenodo.8339691. Enron imports only label 0 legitimate records; Nazario imports label 1 phishing records. Publisher MD5 verified. Sampling seed {seed}.'
    records=[core.normalize(r,cfg['name'],'public_dataset',url,cfg['label'],intended,notes) for r in selected]
    (cache/f'{key}_provenance.json').write_text(json.dumps({'url':url,'publisher':'https://zenodo.org/records/8339691','checksum_md5':digest,'sha256':core.checksum(path),'source_rows_matching_label':seen,'imported':len(records),'sample_seed':seed},indent=2))
    return core.dedup(records)
