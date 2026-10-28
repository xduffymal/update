"""Persistent, reproducible email/URL experiments. Never import scan history into training."""
import csv
import hashlib
import io
import json
import os
import platform
import re
import sqlite3
import time
import uuid
import threading
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(os.environ.get('LAB_ROOT', Path(__file__).parent)).resolve()
DB = ROOT / 'cyber_threat.db'
_model_cache={}
_cache_lock=threading.RLock()
FIELDS = ['record_id','subject','body','sender','reply_to','urls','attachment_names','label','source','source_type','original_label','collected_at','origin','reviewed','split_assignment','intended_use','usage_notes']
COMPAT = {'word': ['Logistic Regression','Naive Bayes','Linear SVM','Random Forest'], 'character': ['URL Logistic Regression'], 'embeddings': ['LSTM'], 'contextual': ['BERT','CTI-BERT']}
COMPAT['compare']=COMPAT['word']+COMPAT['embeddings']+COMPAT['contextual']

def now():
    return datetime.now(timezone.utc).isoformat()

def connect():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def init():
    for name in ['data/raw','data/processed','data/validation','models/versions','results','uploads']:
        (ROOT / name).mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS dataset_imports(id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at TEXT);
        CREATE TABLE IF NOT EXISTS training_runs(id TEXT PRIMARY KEY, status TEXT, metadata TEXT, error TEXT);
        CREATE TABLE IF NOT EXISTS model_versions(id TEXT PRIMARY KEY, run_id TEXT, name TEXT, artifact TEXT, metadata TEXT);
        CREATE TABLE IF NOT EXISTS deployed_models(kind TEXT PRIMARY KEY, version TEXT, previous TEXT, user TEXT, deployed_at TEXT);
        CREATE TABLE IF NOT EXISTS email_scans(id TEXT PRIMARY KEY, result TEXT, created_at TEXT, user TEXT);
        CREATE TABLE IF NOT EXISTS analyst_feedback(id TEXT PRIMARY KEY, scan_id TEXT, label TEXT, sanitized_text TEXT, status TEXT, user TEXT, approver TEXT);
        CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, action TEXT, user TEXT, details TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS system_jobs(id TEXT PRIMARY KEY, status TEXT, metadata TEXT, error TEXT);
        CREATE TABLE IF NOT EXISTS dataset_records(dataset_id TEXT,record_id TEXT,metadata TEXT,PRIMARY KEY(dataset_id,record_id));
        CREATE TABLE IF NOT EXISTS model_metrics(version TEXT PRIMARY KEY,metrics TEXT);
        CREATE TABLE IF NOT EXISTS url_findings(id TEXT PRIMARY KEY,scan_id TEXT,metadata TEXT);
        CREATE TABLE IF NOT EXISTS attachment_findings(id TEXT PRIMARY KEY,scan_id TEXT,metadata TEXT);
        CREATE TABLE IF NOT EXISTS scan_findings(id TEXT PRIMARY KEY,scan_id TEXT,finding TEXT);
        CREATE TABLE IF NOT EXISTS email_indicators(id TEXT PRIMARY KEY,scan_id TEXT,metadata TEXT);
        CREATE TABLE IF NOT EXISTS email_alerts(id TEXT PRIMARY KEY,scan_id TEXT,classification TEXT,risk_score REAL,created_at TEXT);
        CREATE TABLE IF NOT EXISTS batch_jobs(id TEXT PRIMARY KEY,user TEXT,scan_ids TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS system_settings(key TEXT PRIMARY KEY,value TEXT);
        ''')

def audit(action, user, details):
    with connect() as c:
        c.execute('INSERT INTO audit_logs(action,user,details,created_at) VALUES(?,?,?,?)',(action,user,json.dumps(details),now()))

def rows(table):
    if table not in {'dataset_imports','training_runs','model_versions','deployed_models','email_scans','analyst_feedback','audit_logs','users','reports','feed_runs','system_jobs','email_alerts','batch_jobs','url_findings','attachment_findings','email_indicators','system_settings'}:
        raise ValueError('Unknown table')
    with connect() as c:
        return [dict(r) for r in c.execute(f'SELECT * FROM {table} ORDER BY rowid DESC')]

def artifact(relative):
    p = (ROOT / relative).resolve()
    if not p.is_relative_to(ROOT) or p == ROOT:
        raise ValueError('Invalid file path')
    return p

def checksum(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def write_csv(path, records, fields=FIELDS):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(records)

def read_csv(path):
    csv.field_size_limit(16*1024*1024)
    with path.open(encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))

def fingerprint(r):
    # Ignore provenance and message ID when identifying duplicate content.
    text = (r.get('subject','') + ' ' + r.get('body','')).strip() or r.get('urls','')
    return hashlib.sha256(re.sub(r'\s+',' ',text.lower()).strip().encode()).hexdigest()

def dedup(records):
    seen = {}
    for r in records:
        key = fingerprint(r)
        if key in seen and seen[key]['label'] != r['label']:
            raise ValueError('Identical content has conflicting labels. Resolve the labels before saving.')
        if key in seen and seen[key].get('split_assignment','unassigned') != r.get('split_assignment','unassigned'):
            raise ValueError('Duplicate content crosses assigned splits; keep validation and testing separate.')
        seen.setdefault(key,r)
    return list(seen.values())

class SafeHTML(HTMLParser):
    def __init__(self):
        super().__init__(); self.text=[]; self.links=[]; self.hidden=0; self.displayed_links=[]; self.current_link=None
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style'): self.hidden+=1
        if tag=='a':
            href=dict(attrs).get('href','')
            if href.startswith(('http://','https://')):
                self.links.append(href); self.current_link={'destination':href,'displayed':''}
    def handle_endtag(self,tag):
        if tag in ('script','style'): self.hidden=max(0,self.hidden-1)
        if tag=='a' and self.current_link:
            self.displayed_links.append(self.current_link); self.current_link=None
    def handle_data(self,data):
        if not self.hidden: self.text.append(data)
        if self.current_link: self.current_link['displayed']+=data

def extract_urls(text):
    return sorted(set(u.rstrip('.,;)>]') for u in re.findall(r'https?://[^\s<>"\x27]+',text)))

def attachment_info(name, content, mime='application/octet-stream'):
    from attachment_safety import inspect
    return inspect(name,content,mime)
    # Historical implementation is kept below until the next cleanup migration.
    ext = Path(name).suffix.lower()
    findings=[]
    if ext in {'.exe','.com','.bat','.cmd','.ps1','.js','.vbs','.scr','.msi'}: findings.append('Executable or script: malware risk')
    if ext in {'.docm','.xlsm','.pptm'}: findings.append('Macro-enabled document')
    if ext in {'.zip','.rar','.7z'}: findings.append('Archive requires manual inspection; contents not executed or extracted')
    if re.search(r'\.(pdf|docx|txt|jpg)\.', name, re.I): findings.append('Double extension')
    if ext=='.pdf' and not content.startswith(b'%PDF'): findings.append('Extension and file signature mismatch')
    if ext in {'.docx','.xlsx','.zip'} and not content.startswith(b'PK'): findings.append('Extension and file signature mismatch')
    urls=extract_urls(content.decode('utf-8','replace')) if ext in {'.txt','.csv'} else []
    return {'name':name,'extension':ext,'mime':mime,'size':len(content),'sha256':hashlib.sha256(content).hexdigest(),'findings':findings,'urls':urls}

def parse_email(content, filename):
    ext=Path(filename).suffix.lower()
    if ext=='.txt': return {'subject':'','body':content.decode('utf-8-sig','replace'),'sender':'','reply_to':'','urls':[],'attachments':[],'headers':{}}
    if ext=='.msg':
        try:
            import extract_msg
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.msg',dir=ROOT/'uploads',delete=False) as f:
                f.write(content); temporary=Path(f.name)
            try:
                with extract_msg.Message(str(temporary)) as msg:
                    html=msg.htmlBody or b''; parser=SafeHTML(); parser.feed(html.decode('utf-8','replace') if isinstance(html,bytes) else html)
                    body=msg.body or '\n'.join(parser.text)
                    attachments=[]
                    for attachment in msg.attachments:
                        data=attachment.data
                        if isinstance(data,bytes): attachments.append(attachment_info(attachment.longFilename or attachment.shortFilename or 'unnamed',data,getattr(attachment,'mimetype',None) or 'application/octet-stream'))
                    return {'subject':msg.subject or '', 'body':body,'sender':msg.sender or '', 'reply_to':'','urls':sorted(set(parser.links+extract_urls(body))), 'displayed_links':parser.displayed_links,'attachments':attachments,'headers':{'From':msg.sender or '','To':msg.to or '','Date':str(msg.date or '')}}
            finally: temporary.unlink(missing_ok=True)
        except ImportError: raise ValueError('MSG parsing dependency missing. Install extract-msg.')
        except Exception as error: raise ValueError('MSG file could not be parsed: '+str(error))
    if ext!='.eml': raise ValueError('Use an EML or TXT email file.')
    msg=BytesParser(policy=policy.default).parsebytes(content)
    plain=[]; html=[]; links=[]; displayed_links=[]; attachments=[]
    for part in msg.walk():
        if part.is_multipart(): continue
        if part.get_content_disposition()=='attachment' or part.get_filename():
            attachments.append(attachment_info(part.get_filename() or 'unnamed',part.get_payload(decode=True) or b'',part.get_content_type())); continue
        if part.get_content_type() in ('text/plain','text/html'):
            try: text=part.get_content()
            except (LookupError,UnicodeError): text=(part.get_payload(decode=True) or b'').decode('utf-8','replace')
            if part.get_content_type()=='text/plain': plain.append(text)
            else:
                parser=SafeHTML(); parser.feed(text); html.extend(parser.text); links.extend(parser.links); displayed_links.extend(parser.displayed_links)
    body='\n'.join(plain or html)
    return {'subject':str(msg.get('Subject','')),'body':body,'sender':str(msg.get('From','')),'reply_to':str(msg.get('Reply-To','')),'urls':sorted(set(links+extract_urls(body))),'displayed_links':displayed_links,'attachments':attachments,'headers':{k:str(msg.get(k,'')) for k in ['From','To','Reply-To','Date','Message-ID','Authentication-Results']}}

def parse_upload(content,filename):
    if len(content)>8*1024*1024: raise ValueError('Each file must be at most 8 MB.')
    if Path(filename).suffix.lower()=='.mbox':
        chunks=re.split(br'(?m)^From [^\r\n]+\r?\n',content)
        return [parse_email(chunk,'message.eml') for chunk in chunks if chunk.strip()]
    return [parse_email(content,filename)]

def normalize(record, source, source_type, origin, label, intended, notes, reviewed=False):
    original=str(record.get('label') or label).strip()
    mapped={'0':'legitimate','ham':'legitimate','benign':'legitimate','legitimate':'legitimate','1':'phishing','spam':'phishing','phishing':'phishing','malicious':'phishing'}
    if original.lower() not in mapped: raise ValueError(f'Unsupported label {original!r}; use legitimate/phishing or 0/1. Spam is mapped to phishing only when you explicitly accept that dataset labeling.')
    body=str(record.get('body') or record.get('text') or record.get('content') or record.get('email') or record.get('url') or '').strip()
    subject=str(record.get('subject') or '').strip()
    if not body and not subject: raise ValueError('A record is missing text or a URL.')
    urls=record.get('urls') or record.get('url') or extract_urls(body)
    if isinstance(urls,list): urls=' '.join(urls)
    assignment=record.get('split_assignment') or ('validation' if intended=='validation' else 'unassigned')
    if assignment not in {'training','testing','validation','unassigned'}: raise ValueError('Invalid split assignment.')
    names=record.get('attachment_names') or '; '.join(a['name'] for a in record.get('attachments',[]))
    return dict(zip(FIELDS,[uuid.uuid4().hex,subject,body,str(record.get('sender','')),str(record.get('reply_to','')),urls,str(names),mapped[original.lower()],source,source_type,original,now(),origin,str(bool(reviewed)).lower(),assignment,intended,notes]))

def collect(files,source,label,intended,notes,reviewed=False,field_map=None):
    if not source.strip(): raise ValueError('Enter the real source name.')
    records=[]
    for filename,content in files:
        if len(content)>8*1024*1024: raise ValueError('Each file must be at most 8 MB.')
        ext=Path(filename).suffix.lower()
        if ext=='.csv':
            incoming=list(csv.DictReader(io.StringIO(content.decode('utf-8-sig'))))
            if not incoming: raise ValueError('CSV is empty.')
            for target,column in (field_map or {}).items():
                if column:
                    if column not in incoming[0]: raise ValueError(f'CSV column {column!r} was not found.')
                    for record in incoming: record[target]=record[column]
        else: incoming=parse_upload(content,filename)
        records.extend(normalize(r,source,ext.lstrip('.'),Path(filename).name,label,intended,notes,reviewed) for r in incoming)
    return records

def save_dataset(records,user):
    records=dedup(records)
    if not records: raise ValueError('No imported records to save.')
    ident=uuid.uuid4().hex
    folder='validation' if all(r['split_assignment']=='validation' for r in records) else 'processed'
    if folder=='validation':
        validation_hashes=set(map(fingerprint,records))
        for existing_split in splits():
            used=read_csv(artifact(existing_split['train']))+read_csv(artifact(existing_split['test']))
            if validation_hashes & set(map(fingerprint,used)):
                raise ValueError('Validation content already belongs to an experiment split. Supply independent records.')
    filename=f'data/{folder}/dataset_{ident}.csv'
    write_csv(artifact(filename),records)
    metadata={'filename':filename,'checksum':checksum(artifact(filename)),'records':len(records),'classes':dict(Counter(r['label'] for r in records)),'sources':sorted(set(r['source'] for r in records)),'created_at':now(),'user':user}
    with connect() as c:
        c.execute('INSERT INTO dataset_imports VALUES(?,?,?)',(ident,json.dumps(metadata),now()))
        c.executemany('INSERT INTO dataset_records VALUES(?,?,?)',[(ident,r['record_id'],json.dumps(r)) for r in records])
    manifest=ROOT/'data/dataset_manifest.csv'
    fields=['dataset','source','source_type','collected_at','records','legitimate','phishing','intended_use','usage_notes','checksum','reviewed']
    existing=read_csv(manifest) if manifest.exists() else []
    for source in metadata['sources']:
        rr=[r for r in records if r['source']==source]
        existing.append(dict(zip(fields,[filename,source,';'.join(sorted(set(r['source_type'] for r in rr))),now(),len(rr),sum(r['label']=='legitimate' for r in rr),sum(r['label']=='phishing' for r in rr),';'.join(sorted(set(r['intended_use'] for r in rr))),';'.join(sorted(set(r['usage_notes'] for r in rr))),metadata['checksum'],all(r['reviewed']=='true' for r in rr)])))
    write_csv(manifest,existing,fields)
    audit('save_dataset',user,metadata)
    return metadata

def split_dataset(filename,ratio,seed,user):
    if ratio not in {0.2,0.25,0.3}: raise ValueError('Choose 80/20, 75/25 or 70/30.')
    records=dedup(read_csv(artifact(filename)))
    if any(r['split_assignment']!='unassigned' or r['intended_use']!='training' for r in records):
        raise ValueError('Only unassigned data permitted for training can be divided. Validation and testing data stay separate.')
    counts=Counter(r['label'] for r in records)
    candidate_fingerprints=set(map(fingerprint,records))
    candidate_urls=set(u.lower() for r in records for u in extract_urls(r.get('urls','')+' '+r.get('body','')))
    for validation in (ROOT/'data/validation').glob('*.csv'):
        vr=read_csv(validation)
        validation_urls=set(u.lower() for r in vr for u in extract_urls(r.get('urls','')+' '+r.get('body','')))
        if candidate_fingerprints & set(map(fingerprint,vr)) or candidate_urls & validation_urls:
            raise ValueError('Training content overlaps an independent validation dataset. Remove those records before division.')
    if set(counts)!={'legitimate','phishing'} or min(counts.values())<4: raise ValueError('Use both classes, with at least four unique records per class; more data is recommended.')
    train,test=train_test_split(records,test_size=ratio,random_state=seed,stratify=[r['label'] for r in records])
    train_urls=set(u.lower() for r in train for u in extract_urls(r.get('urls','')+' '+r.get('body','')))
    test_urls=set(u.lower() for r in test for u in extract_urls(r.get('urls','')+' '+r.get('body','')))
    if train_urls & test_urls:
        train,test=grouped_split(records,ratio,seed)
    ident=uuid.uuid4().hex
    folder=ROOT/'data/processed'/ident; folder.mkdir()
    for assignment,items in [('training',train),('testing',test)]:
        for r in items: r['split_assignment']=assignment
        write_csv(folder/f'{assignment}_set.csv',items)
    settings={'id':ident,'dataset':filename,'dataset_checksum':checksum(artifact(filename)),'train':str((folder/'training_set.csv').relative_to(ROOT)),'test':str((folder/'testing_set.csv').relative_to(ROOT)),'train_checksum':checksum(folder/'training_set.csv'),'test_checksum':checksum(folder/'testing_set.csv'),'train_count':len(train),'test_count':len(test),'classes':dict(counts),'ratio':ratio,'actual_test_ratio':len(test)/len(records),'grouped_shared_urls':bool(train_urls & test_urls),'seed':seed,'created_at':now()}
    (folder/'split.json').write_text(json.dumps(settings,indent=2))
    audit('split_dataset',user,settings)
    return settings

def grouped_split(records,ratio,seed):
    """Keep transitively shared URLs/messages together; deterministic ratio balancing."""
    parent=list(range(len(records)))
    def root(i):
        while parent[i]!=i: parent[i]=parent[parent[i]]; i=parent[i]
        return i
    first={}
    for i,r in enumerate(records):
        for url in extract_urls(r.get('urls','')+' '+r.get('body','')):
            key=url.lower()
            if key in first: parent[root(i)]=root(first[key])
            else: first[key]=i
    grouped={}
    for i,r in enumerate(records): grouped.setdefault(root(i),[]).append(r)
    ids=list(grouped)
    if len(ids)<4: raise ValueError('Too few independent URL/message groups for a safe split. Collect more diverse messages.')
    labels=[Counter(r['label'] for r in grouped[i]).most_common(1)[0][0] for i in ids]
    stratify=labels if len(set(labels))==2 and min(Counter(labels).values())>=2 else None
    best=None
    for attempt in range(64):
        try: tr,te=train_test_split(ids,test_size=ratio,random_state=(seed+attempt)%4294967295,stratify=stratify)
        except ValueError: tr,te=train_test_split(ids,test_size=ratio,random_state=(seed+attempt)%4294967295)
        a=[r for group in tr for r in grouped[group]]; b=[r for group in te for r in grouped[group]]
        ca=Counter(r['label'] for r in a); cb=Counter(r['label'] for r in b)
        if set(ca)!={'legitimate','phishing'} or set(cb)!={'legitimate','phishing'} or min(ca.values())<2: continue
        score=abs(len(b)/len(records)-ratio)+abs(cb['phishing']/len(b)-sum(r['label']=='phishing' for r in records)/len(records))
        if best is None or score<best[0]: best=(score,a,b)
    if best is None: raise ValueError('Shared-URL groups cannot form both classes in train and test; collect more diverse data.')
    return best[1],best[2]

def splits():
    return [json.loads(p.read_text()) for p in sorted((ROOT/'data/processed').glob('*/split.json'),key=lambda p:p.stat().st_mtime,reverse=True)]

def set_status(run,status,metadata=None,error=None):
    with connect() as c:
        if metadata is None: c.execute('UPDATE training_runs SET status=?,error=? WHERE id=?',(status,error,run))
        else: c.execute('UPDATE training_runs SET status=?,metadata=?,error=? WHERE id=?',(status,json.dumps(metadata),error,run))

def make_pipeline(feature,name,seed,calibration_folds=3):
    if name not in COMPAT.get(feature,[]): raise ValueError('Incompatible feature and model combination.')
    vector=TfidfVectorizer(lowercase=True,strip_accents='unicode',max_features=30000,ngram_range=(1,2)) if feature=='word' else TfidfVectorizer(lowercase=True,analyzer='char',ngram_range=(2,5),max_features=50000)
    estimators={'Logistic Regression':lambda:LogisticRegression(max_iter=1000,random_state=seed),'URL Logistic Regression':lambda:LogisticRegression(max_iter=1000,random_state=seed),'Naive Bayes':MultinomialNB,'Random Forest':lambda:RandomForestClassifier(n_estimators=100,random_state=seed,n_jobs=1)}
    base=Pipeline([('features',vector),('model',LinearSVC(random_state=seed) if name=='Linear SVM' else estimators[name]())])
    # Fit the vectorizer inside each calibration fold, not on its held-out samples.
    return CalibratedClassifierCV(base,cv=calibration_folds) if name=='Linear SVM' else base

def texts(records,feature):
    if feature=='character':
        values=[]
        for r in records:
            urls=extract_urls(r.get('urls','')+' '+r.get('body',''))
            if len(urls)!=1: raise ValueError('URL training requires exactly one complete HTTP(S) URL per record.')
            values.append(urls[0].lower())
        return values
    return [(r['subject']+' '+r['body']).strip() for r in records]

def train_run(run,split,feature,names,user):
    started=time.perf_counter()
    requested_feature=feature
    try:
        if split.get('synthetic'): raise ValueError('Use Preprocessing & Correlation for the synthetic multiclass demonstration.')
        if not names or any(n not in COMPAT.get(feature,[]) for n in names): raise ValueError('Incompatible feature and model combination.')
        set_status(run,'Preprocessing')
        train=read_csv(artifact(split['train'])); test=read_csv(artifact(split['test']))
        if checksum(artifact(split['train']))!=split['train_checksum'] or checksum(artifact(split['test']))!=split['test_checksum']: raise ValueError('Split files changed; create a new split.')
        if set(map(fingerprint,train)) & set(map(fingerprint,test)): raise ValueError('Training/testing duplicate leakage detected.')
        if any(r['split_assignment']!='training' for r in train) or any(r['split_assignment']!='testing' for r in test): raise ValueError('Invalid split assignment.')
        x=texts(train,feature); xt=texts(test,feature); y=[r['label'] for r in train]; yt=[r['label'] for r in test]
        if feature=='character' and not any(urlsplit(t).path not in {'','/'} for t,label in zip(x,y) if label=='legitimate'):
            raise ValueError('Include legitimate login-page URLs, not just homepages, in the URL training dataset.')
        output=[]
        folds=min(3,min(Counter(y).values()))
        if folds<2: raise ValueError('Not enough training records for calibration/cross-validation.')
        for name in names:
            feature=('embeddings' if name=='LSTM' else 'contextual' if name in {'BERT','CTI-BERT'} else 'word') if requested_feature=='compare' else requested_feature
            set_status(run,'Training')
            t=time.perf_counter()
            if feature in {'embeddings','contextual'}:
                from neural_training import train_neural
                def progress(done,total):
                    set_status(run,'Training',{'split':split,'feature':requested_feature,'names':names,'user':user,'current_model':name,'progress':round(100*done/total)})
                estimator,params=train_neural(x,y,name,split['seed'],progress)
                cv=params.get('cross_validation_macro_f1')
                if name=='LSTM':
                    import numpy as np
                    from sklearn.metrics import f1_score
                    scores=[]
                    for fold,(a,b) in enumerate(StratifiedKFold(n_splits=folds,shuffle=True,random_state=split['seed']).split(x,y)):
                        folded,_=train_neural([x[i] for i in a],[y[i] for i in a],name,split['seed'])
                        scores.append(float(f1_score([y[i] for i in b],folded.predict([x[i] for i in b]),average='macro',zero_division=0)))
                        progress(fold+1,folds)
                    cv=float(np.mean(scores)); params['cross_validation_macro_f1']=cv
            else:
                estimator=make_pipeline(feature,name,split['seed'],min(3,min(Counter(y).values())))
                # Inner SVM calibration requires >=2 examples/class in each outer training fold.
                cv_est=make_pipeline(feature,name,split['seed'],2)
                cv=float(cross_val_score(cv_est,x,y,cv=StratifiedKFold(n_splits=folds,shuffle=True,random_state=split['seed']),scoring='f1_macro').mean()) if name!='Linear SVM' or min(Counter(y).values())>=4 else None
                estimator.fit(x,y); params=repr(estimator.get_params())
            duration=time.perf_counter()-t
            set_status(run,'Evaluating')
            t=time.perf_counter(); predicted=estimator.predict(xt); test_time=time.perf_counter()-t
            precision,recall,f1,_=precision_recall_fscore_support(yt,predicted,pos_label='phishing',average='binary',zero_division=0)
            mp,mr,mf,_=precision_recall_fscore_support(yt,predicted,average='macro',zero_division=0)
            matrix=confusion_matrix(yt,predicted,labels=['legitimate','phishing']).tolist()
            version=uuid.uuid4().hex; version_dir=artifact(f'models/versions/{version}'); version_dir.mkdir()
            path=f'models/versions/{version}/pipeline.joblib'; joblib.dump(estimator,artifact(path))
            vectorizer_file=path+' (embedded calibration-fold vectorizers)' if name=='Linear SVM' or feature in {'embeddings','contextual'} else f'models/versions/{version}/'+('url_tfidf_vectorizer.pkl' if feature=='character' else 'tfidf_vectorizer.pkl')
            model_file=path
            if feature in {'word','character'} and name!='Linear SVM':
                joblib.dump(estimator.named_steps['features'],artifact(vectorizer_file))
                model_file=f'models/versions/{version}/'+('phishing_url_model.pkl' if feature=='character' else 'model.pkl')
                joblib.dump(estimator.named_steps['model'],artifact(model_file))
            metrics={'version':version,'name':name,'feature':feature,'accuracy':float(accuracy_score(yt,predicted)),'precision':float(precision),'recall':float(recall),'f1':float(f1),'macro_precision':float(mp),'macro_recall':float(mr),'macro_f1':float(mf),'cross_validation_macro_f1':cv,'training_seconds':duration,'testing_seconds':test_time,'confusion_matrix':matrix,'correct':sum(a==b for a,b in zip(yt,predicted)),'incorrect':sum(a!=b for a,b in zip(yt,predicted)),'false_positives':matrix[0][1],'false_negatives':matrix[1][0],'per_class':classification_report(yt,predicted,output_dict=True,zero_division=0),'parameters':params,'artifact':path,'kind':'url' if feature=='character' else 'email'}
            metrics.update(model_file=model_file,vectorizer_file=vectorizer_file,confidence_method='cross-validated sigmoid calibration' if name=='Linear SVM' else 'uncalibrated softmax' if feature=='embeddings' else 'model probability estimate; calibration not guaranteed')
            (version_dir/('url_model_metadata.json' if feature=='character' else 'model_metadata.json')).write_text(json.dumps(metrics,indent=2))
            with connect() as c:
                c.execute('INSERT INTO model_versions VALUES(?,?,?,?,?)',(version,run,name,path,json.dumps(metrics)))
                c.execute('INSERT INTO model_metrics VALUES(?,?)',(version,json.dumps(metrics)))
            output.append(metrics)
            write_csv(ROOT/f'results/{run}_{version}_errors.csv',[{'record_id':r['record_id'],'expected':truth,'predicted':pred} for r,truth,pred in zip(test,yt,predicted) if truth!=pred],['record_id','expected','predicted'])
        import importlib.metadata
        libraries={package:importlib.metadata.version(package) for package in ['flask','scikit-learn','joblib','numpy','scipy','pandas','nltk']}
        for package in ['torch','transformers','safetensors']:
            try: libraries[package]=importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError: pass
        metadata={'run_id':run,'split':split,'models':output,'user':user,'created_at':now(),'duration':time.perf_counter()-started,'preprocessing':{'feature':requested_feature,'per_model':{m['name']:{'feature':m['feature'],'parameters':m['parameters']} for m in output}},'versions':{'python':platform.python_version(),**libraries},'class_distribution':{'training':dict(Counter(y)),'testing':dict(Counter(yt))}}
        (ROOT/f'results/{run}.json').write_text(json.dumps(metadata,indent=2))
        write_csv(ROOT/f'results/{run}_comparison.csv',output,['version','name','feature','accuracy','precision','recall','f1','macro_f1','cross_validation_macro_f1','false_positives','false_negatives','training_seconds','testing_seconds'])
        set_status(run,'Completed',metadata); audit('training_completed',user,{'run':run})
    except Exception as e:
        set_status(run,'Failed',error=str(e)); audit('training_failed',user,{'run':run,'error':str(e)})

def deploy(version,user):
    with connect() as c:
        row=c.execute('SELECT * FROM model_versions WHERE id=?',(version,)).fetchone()
        if not row: raise ValueError('Unknown model version.')
        metrics=json.loads(row['metadata']); kind=metrics['kind']
        run=c.execute('SELECT status FROM training_runs WHERE id=?',(row['run_id'],)).fetchone()
        if not run or run['status']!='Completed': raise ValueError('Only a completed experiment may be deployed.')
        if not artifact(row['artifact']).exists(): raise ValueError('Model artifact is missing.')
        old=c.execute('SELECT version FROM deployed_models WHERE kind=?',(kind,)).fetchone()
        if old and old[0]==version: raise ValueError('This version is already deployed.')
        c.execute('INSERT OR REPLACE INTO deployed_models VALUES(?,?,?,?,?)',(kind,version,old[0] if old else None,user,now()))
    audit('deploy_model',user,{'version':version,'kind':kind})
    if kind=='threat':
        import sys
        module=sys.modules.get('app')
        if module:
            pipeline=joblib.load(artifact(row['artifact'])); module.model=pipeline.named_steps['model']; module.vectorizer=pipeline.named_steps['features']

def rollback(kind,user):
    with connect() as c: row=c.execute('SELECT previous FROM deployed_models WHERE kind=?',(kind,)).fetchone()
    if not row or not row[0]: raise ValueError('No previous model version is available.')
    deploy(row[0],user); audit('rollback_model',user,{'kind':kind})

def model_prediction(kind,text):
    with connect() as c: row=c.execute('SELECT m.* FROM model_versions m JOIN deployed_models d ON m.id=d.version WHERE d.kind=?',(kind,)).fetchone()
    if not row: return {'status':'unavailable','prediction':None,'confidence':None,'phishing_probability':None,'reason':'No model deployed.'}
    try:
        path=artifact(row['artifact']); key=(str(path),path.stat().st_mtime_ns)
        with _cache_lock:
            if key not in _model_cache:
                _model_cache[key]=joblib.load(path)
                while len(_model_cache)>2: _model_cache.pop(next(iter(_model_cache)))
            estimator=_model_cache[key]
        probs=estimator.predict_proba([text])[0]; classes=list(estimator.classes_); i=int(probs.argmax())
        return {'status':'available','prediction':classes[i],'confidence':float(probs[i]),'phishing_probability':float(probs[classes.index('phishing')]),'version':row['id'],'confidence_method':json.loads(row['metadata']).get('confidence_method','model estimate')}
    except Exception as e: return {'status':'unavailable','prediction':None,'confidence':None,'phishing_probability':None,'reason':str(e)}

def analyze(email,user):
    text=email.get('subject','')+' '+email['body']; email_model=model_prediction('email',text)
    urls=sorted(set(email.get('urls',[])+extract_urls(text))); findings=[]; url_results=[]
    urls=sorted(set(urls+[url for a in email.get('attachments',[]) for url in a.get('urls',[])]))
    for url in urls:
        try:
            parsed=urlsplit(url); host=parsed.hostname or ''; flags=[]
            if parsed.username or '@' in url: flags.append('At-sign or embedded user information')
            if re.fullmatch(r'[\d.]+',host): flags.append('IP-address host')
            if 'xn--' in host: flags.append('Punycode host')
            if len(url)>120: flags.append('Long URL')
            if host in {'bit.ly','t.co','tinyurl.com','shorturl.at'}: flags.append('URL shortener')
            if len(host.split('.'))>4: flags.append('Many subdomains')
            if re.search(r'(?:www|com)[-.].*(?:www|com)',host,re.I): flags.append('Repeated www/com domain markers')
            parts=host.split('.')
            if len(parts)>2 and len(set(parts))<len(parts): flags.append('Repeated domain segments')
            from email.utils import parseaddr
            sender_address=parseaddr(email.get('sender',''))[1]
            sender_domain=sender_address.rsplit('@',1)[-1].lower() if '@' in sender_address else ''
            if sender_domain and not (host==sender_domain or host.endswith('.'+sender_domain)):
                flags.append('Sender and destination domains differ; third-party services may explain this')
            for link in email.get('displayed_links',[]):
                displayed=extract_urls(link['displayed'])
                if link['destination']==url and displayed and urlsplit(displayed[0]).hostname!=parsed.hostname:
                    flags.append('Displayed link domain differs from destination')
            stats={'url_length':len(url),'domain_length':len(host),'subdomain_length':len('.'.join(parts[:-2])),'subdomain_count':max(0,len(parts)-2),'path_length':len(parsed.path),'digits':sum(c.isdigit() for c in url),'special_characters':sum(not c.isalnum() for c in url),'sensitive_words':[w for w in ['login','verify','secure','account','update','password','payment','confirm'] if w in url.lower()]}
            pred=model_prediction('url',url.lower()); url_results.append({'url':url,'model':pred,'findings':flags,'features':stats})
        except ValueError: url_results.append({'url':url,'model':{'status':'unavailable'},'findings':['Malformed URL'],'features':{}})
    if re.search(r'urgent|immediately|suspend|verify your|confirm your|password|wire transfer',text,re.I): findings.append('Urgency or credential/payment language')
    auth=email.get('headers',{}).get('Authentication-Results','').lower()
    if re.search(r'(spf|dkim|dmarc)=fail',auth): findings.append('Email authentication failure reported in supplied headers (not independently verified)')
    if email.get('reply_to') and email.get('sender') and email['reply_to'].lower()!=email['sender'].lower(): findings.append('Reply-To differs from sender; inspect addresses')
    attachments=email.get('attachments',[])
    flags=sum(len(u['findings']) for u in url_results)+len(findings)+sum(len(a['findings']) for a in attachments)
    rule_score=min(100,flags*20)
    components=[(0.55,100*email_model['phishing_probability'])] if email_model['status']=='available' else []
    url_probs=[u['model']['phishing_probability'] for u in url_results if u['model']['status']=='available']
    if url_probs: components.append((0.25,100*max(url_probs)))
    components.append((0.20,rule_score)); risk=sum(w*s for w,s in components)/sum(w for w,s in components)
    classification='Phishing' if risk>=70 else 'Suspicious' if risk>=35 else 'Legitimate'
    if email_model['status']!='available' and classification=='Legitimate': classification='Suspicious'; findings.append('No email model available: manual review required')
    level='Critical' if risk>=90 else 'High' if risk>=70 else 'Medium' if risk>=35 or classification=='Suspicious' else 'Low'
    entities={'cves':sorted(set(re.findall(r'CVE-\d{4}-\d{4,}',text,re.I))),'attack_techniques':sorted(set(re.findall(r'\bT\d{4}(?:\.\d{3})?\b',text))),'actor_mentions':sorted(set(re.findall(r'\b(?:APT\d+|FIN\d+|Lazarus)\b',text,re.I))),'malware_type_mentions':sorted(set(re.findall(r'\b(?:ransomware|trojan|botnet|spyware|keylogger)\b',text,re.I))),'urls':urls}
    correlations=[]
    with connect() as c:
        for prior in c.execute('SELECT id,result FROM email_scans ORDER BY rowid DESC LIMIT 500'):
            saved=json.loads(prior['result']); shared=set(urls)&{u['url'] for u in saved.get('urls',[])}
            if shared: correlations.append({'scan_id':prior['id'],'shared_urls':sorted(shared),'classification':saved['classification']})
        tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'indicators' in tables:
            for indicator in urls+entities['cves']:
                matches=c.execute('SELECT report_id,indicator_type FROM indicators WHERE lower(indicator_value)=lower(?) LIMIT 10',(indicator,)).fetchall()
                correlations.extend({'report_id':m['report_id'],'indicator':indicator,'type':m['indicator_type']} for m in matches)
    result={'id':uuid.uuid4().hex,'email':email,'email_model':email_model,'urls':url_results,'entities':entities,'correlations':correlations,'rule_findings':findings,'rule_score':rule_score,'risk_score':round(risk,2),'classification':classification,'risk_level':level,'recommendation':'Quarantine and investigate; do not interact with links or attachments.' if classification=='Phishing' else 'Review sender and evidence before taking action.' if classification=='Suspicious' else 'No strong phishing evidence found; continue normal caution.','created_at':now()}
    with connect() as c:
        c.execute('INSERT INTO email_scans VALUES(?,?,?,?)',(result['id'],json.dumps(result),now(),user))
        c.executemany('INSERT INTO url_findings VALUES(?,?,?)',[(uuid.uuid4().hex,result['id'],json.dumps(u)) for u in url_results])
        c.executemany('INSERT INTO attachment_findings VALUES(?,?,?)',[(uuid.uuid4().hex,result['id'],json.dumps(a)) for a in attachments])
        c.executemany('INSERT INTO scan_findings VALUES(?,?,?)',[(uuid.uuid4().hex,result['id'],f) for f in findings])
        c.execute('INSERT INTO email_indicators VALUES(?,?,?)',(uuid.uuid4().hex,result['id'],json.dumps(entities)))
        if risk>=70: c.execute('INSERT INTO email_alerts VALUES(?,?,?,?,?)',(uuid.uuid4().hex,result['id'],classification,risk,now()))
    return result
