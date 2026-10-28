"""Recover the separate three-class threat-report workflow without replacing history."""
import json
import re
import uuid
import time
import platform
import importlib.metadata
import requests
import truststore
import joblib
from collections import Counter
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report,accuracy_score,confusion_matrix
import lab_core as core
truststore.inject_into_ssl()

FEEDS={'NVD':'https://services.nvd.nist.gov/rest/json/cves/2.0','MITRE ATT&CK':'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json','OpenPhish':'https://openphish.com/feed.txt'}

def collect(source,limit,user_id,user,notes):
    if source not in FEEDS or not 5<=limit<=100: raise ValueError('Choose a supported feed and 5–100 records.')
    if not notes.strip(): raise ValueError('Record the permitted use / attribution for this feed.')
    url=FEEDS[source]
    response=requests.get(url,params={'resultsPerPage':limit} if source=='NVD' else None,timeout=(30,90)); response.raise_for_status()
    records=[]
    if source=='NVD':
        for entry in response.json().get('vulnerabilities',[]):
            cve=entry['cve']; description=next((d['value'] for d in cve.get('descriptions',[]) if d['lang']=='en'),'')
            if description: records.append((cve['id'],description,'vulnerability'))
    elif source=='MITRE ATT&CK':
        for obj in response.json().get('objects',[]):
            if obj.get('type')=='attack-pattern' and not obj.get('revoked') and not obj.get('x_mitre_deprecated') and obj.get('description'):
                records.append((obj['name'],obj['description'],'attack_technique'))
    else:
        for line in response.text.splitlines():
            if line.startswith(('http://','https://')): records.append((line,line,'phishing'))
    records=records[:limit]; added=0
    with core.connect() as c:
        for title,body,label in records:
            if c.execute('SELECT 1 FROM reports WHERE title=? AND source=?',(title,source)).fetchone(): continue
            cursor=c.execute('INSERT INTO reports(title,source,content,uploaded_by) VALUES(?,?,?,?)',(title,source,body,user_id)); report=cursor.lastrowid
            # Source category is declared provenance, not an ML confidence.
            c.execute('INSERT INTO threat_classifications(report_id,threat_type,severity,confidence_score) VALUES(?,?,?,?)',(report,label,'Unassessed',None))
            for value in core.extract_urls(body)+re.findall(r'CVE-\d{4}-\d{4,}',body):
                c.execute('INSERT INTO indicators(report_id,indicator_type,indicator_value) VALUES(?,?,?)',(report,'URL' if value.startswith('http') else 'CVE',value))
            added+=1
        c.execute('INSERT INTO feed_runs(source_name,records_fetched,records_added,run_status,notes) VALUES(?,?,?,?,?)',(source,len(records),added,'success',f'{notes} | Source URL: {url}; labels are source categories, not model predictions.'))
    core.audit('collect_threat_feed',user,{'source':source,'fetched':len(records),'added':added,'url':url})
    return added

def train(user):
    started=time.perf_counter()
    with core.connect() as c:
        records=[dict(r) for r in c.execute("SELECT r.report_id,r.title,r.source,r.content FROM reports r WHERE r.source IN ('NVD','MITRE ATT&CK','OpenPhish')")]
    mapping={'NVD':'vulnerability','MITRE ATT&CK':'attack_technique','OpenPhish':'phishing'}
    records=list({core.fingerprint({'subject':r['title'],'body':r['content']}):r for r in records}.values())
    y=[mapping[r['source']] for r in records]; counts=Counter(y)
    if len(counts)!=3 or min(counts.values())<5: raise ValueError('Collect at least five unique NVD, MITRE and OpenPhish records each before training.')
    a,b=train_test_split(records,test_size=.2,random_state=42,stratify=y)
    pipeline=Pipeline([('features',TfidfVectorizer(lowercase=True,ngram_range=(1,2),max_features=30000)),('model',LogisticRegression(max_iter=1000,random_state=42))])
    pipeline.fit([r['content'] for r in a],[mapping[r['source']] for r in a]); target=[mapping[r['source']] for r in b]; prediction=pipeline.predict([r['content'] for r in b])
    version=uuid.uuid4().hex; run=uuid.uuid4().hex; path=core.artifact(f'models/versions/{version}'); path.mkdir()
    joblib.dump(pipeline,path/'pipeline.joblib')
    metadata={'version':version,'name':'Threat-report Logistic Regression','kind':'threat','feature':'threat_word','artifact':str((path/'pipeline.joblib').relative_to(core.ROOT)).replace('\\','/'),'accuracy':float(accuracy_score(target,prediction)),'f1':float(classification_report(target,prediction,output_dict=True,zero_division=0)['macro avg']['f1-score']),'classes':sorted(counts),'confusion_matrix':confusion_matrix(target,prediction,labels=sorted(counts)).tolist(),'per_class':classification_report(target,prediction,output_dict=True,zero_division=0),'confidence_method':'model probability estimate; calibration not guaranteed','seed':42,'class_distribution':dict(counts),'training_records':len(a),'testing_records':len(b),'source_label_note':'Authoritative feed categories; independent generalization is not established','parameters':repr(pipeline.get_params())}
    core.write_csv(core.ROOT/f'results/{run}_threat_records.csv',records,['report_id','title','source','content'])
    metadata['dataset_checksum']=core.checksum(core.ROOT/f'results/{run}_threat_records.csv')
    metadata.update(run_id=run,user=user,created_at=core.now(),duration=time.perf_counter()-started,dataset_filename=f'results/{run}_threat_records.csv',split_ratio=.2,actual_test_ratio=len(b)/len(records),preprocessing={'lowercase':True,'ngram_range':[1,2],'max_features':30000},versions={'python':platform.python_version(),'scikit-learn':importlib.metadata.version('scikit-learn'),'joblib':importlib.metadata.version('joblib')},precision=metadata['per_class']['macro avg']['precision'],recall=metadata['per_class']['macro avg']['recall'],model_file=metadata['artifact'],vectorizer_file=metadata['artifact']+' (embedded)')
    for assignment,items in [('training',a),('testing',b)]:
        filename=f'results/{run}_threat_{assignment}.csv'
        core.write_csv(core.ROOT/filename,[dict(r,label=mapping[r['source']],split_assignment=assignment) for r in items],['report_id','title','source','content','label','split_assignment'])
        metadata[assignment+'_filename']=filename; metadata[assignment+'_checksum']=core.checksum(core.ROOT/filename)
    with core.connect() as c:
        c.execute('INSERT INTO training_runs VALUES(?,?,?,?)',(run,'Completed',json.dumps({'user':user,'models':[metadata],'created_at':core.now(),'experiment_type':'legacy_threat_reports'}),None))
        c.execute('INSERT INTO model_versions VALUES(?,?,?,?,?)',(version,run,metadata['name'],metadata['artifact'],json.dumps(metadata)))
        c.execute('INSERT INTO model_metrics VALUES(?,?)',(version,json.dumps(metadata)))
    (core.ROOT/f'results/{run}_threat_metrics.json').write_text(json.dumps(metadata,indent=2))
    core.audit('train_threat_report_model',user,{'version':version,'run':run})
    return metadata

def load_deployed():
    with core.connect() as c: row=c.execute("SELECT m.artifact FROM model_versions m JOIN deployed_models d ON d.version=m.id WHERE d.kind='threat'").fetchone()
    if not row: return None
    return joblib.load(core.artifact(row['artifact']))
