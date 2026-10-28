"""Evaluate independently assigned records without fitting or deploying models."""
import json
import time
import uuid
from collections import Counter
import joblib
from sklearn.metrics import accuracy_score,confusion_matrix,classification_report,precision_recall_fscore_support
import lab_core as core

def evaluate(filename,versions,user):
    records=core.read_csv(core.artifact(filename))
    if not records or any(r.get('split_assignment')!='validation' for r in records): raise ValueError('Select an independent validation-only dataset.')
    if not versions: raise ValueError('Choose at least one trained model.')
    fingerprints=set(map(core.fingerprint,records)); values=[]; ident=uuid.uuid4().hex
    y=[r['label'] for r in records]
    for version in versions:
        with core.connect() as c:
            row=c.execute('SELECT * FROM model_versions WHERE id=?',(version,)).fetchone()
            if not row: raise ValueError('Unknown model version.')
            run=c.execute('SELECT status,metadata FROM training_runs WHERE id=?',(row['run_id'],)).fetchone()
        if run['status']!='Completed': raise ValueError('Only completed model versions can be validated.')
        split=json.loads(run['metadata'])['split']; used=core.read_csv(core.artifact(split['train']))+core.read_csv(core.artifact(split['test']))
        if fingerprints & set(map(core.fingerprint,used)): raise ValueError('Validation overlaps training/testing content.')
        validation_urls=set(u.lower() for r in records for u in core.extract_urls(r.get('urls','')+' '+r.get('body','')))
        used_urls=set(u.lower() for r in used for u in core.extract_urls(r.get('urls','')+' '+r.get('body','')))
        if validation_urls & used_urls: raise ValueError('Validation URLs overlap the model experiment.')
        metadata=json.loads(row['metadata']); estimator=joblib.load(core.artifact(row['artifact'])); x=core.texts(records,metadata['feature'])
        start=time.perf_counter(); pred=estimator.predict(x); seconds=time.perf_counter()-start
        p,r,f,_=precision_recall_fscore_support(y,pred,average='binary',pos_label='phishing',zero_division=0); matrix=confusion_matrix(y,pred,labels=['legitimate','phishing']).tolist()
        result={'version':version,'name':row['name'],'accuracy':float(accuracy_score(y,pred)),'precision':float(p),'recall':float(r),'f1':float(f),'confusion_matrix':matrix,'false_positives':matrix[0][1],'false_negatives':matrix[1][0],'testing_seconds':seconds,'per_class':classification_report(y,pred,output_dict=True,zero_division=0)}
        values.append(result)
        core.write_csv(core.ROOT/f'results/validation_{ident}_{version}_errors.csv',[{'record_id':rec['record_id'],'expected':truth,'predicted':guess} for rec,truth,guess in zip(records,y,pred) if truth!=guess],['record_id','expected','predicted'])
    saved={'id':ident,'dataset':filename,'checksum':core.checksum(core.artifact(filename)),'records':len(records),'classes':dict(Counter(y)),'models':values,'created_at':core.now(),'user':user}
    (core.ROOT/f'results/validation_{ident}.json').write_text(json.dumps(saved,indent=2))
    core.write_csv(core.ROOT/f'results/validation_{ident}_comparison.csv',values,['version','name','accuracy','precision','recall','f1','false_positives','false_negatives','testing_seconds'])
    core.audit('independent_validation',user,{'id':ident,'dataset':filename,'versions':versions})
    return saved
