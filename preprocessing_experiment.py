"""Controlled preprocessing experiments; select with training CV, evaluate held-out once."""
import json
import re
import time
import uuid
from collections import Counter

import joblib
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
import lab_core as core

METHODS = ['Word counts', 'Word TF-IDF', 'Cleaned TF-IDF', 'Stopword TF-IDF', 'Stemmed TF-IDF', 'Word bigram TF-IDF', 'Character TF-IDF']
EXAMPLE = 'Your account is suspended. Verify your password immediately to restore access.'

class CleanText(BaseEstimator, TransformerMixin):
    def __init__(self, stem=False): self.stem = stem
    def fit(self, x, y=None): return self
    def transform(self, x):
        from nltk.stem import PorterStemmer
        stemmer = PorterStemmer()
        result = []
        for text in x:
            words = re.findall(r'[a-z]+', re.sub(r'https?://\S+', ' urltoken ', text.lower()))
            result.append(' '.join(stemmer.stem(w) if self.stem else w for w in words))
        return result

def pipeline(method, seed):
    options = dict(max_features=30000, lowercase=True, strip_accents='unicode')
    steps = []
    if method in {'Cleaned TF-IDF', 'Stemmed TF-IDF'}:
        steps.append(('clean', CleanText(stem=method == 'Stemmed TF-IDF')))
    if method == 'Word counts': vector = CountVectorizer(**options)
    elif method == 'Character TF-IDF': vector = TfidfVectorizer(analyzer='char', ngram_range=(2,5), **options)
    else:
        vector = TfidfVectorizer(stop_words='english' if method == 'Stopword TF-IDF' else None,
                                 ngram_range=(1,2) if method == 'Word bigram TF-IDF' else (1,1), **options)
    return Pipeline(steps + [('features', vector), ('model', LogisticRegression(max_iter=1000, random_state=seed))])

def correlation(records):
    names = ['Characters', 'Words', 'URLs', 'Exclamation marks', 'Urgent terms', 'Phishing label']
    data = []
    for r in records:
        text = (r.get('subject','') + ' ' + r['body']).strip()
        data.append([len(text), len(text.split()), len(core.extract_urls(text)), text.count('!'),
                     len(re.findall(r'\b(?:urgent|verify|password|suspended|immediately)\b',text.lower())), int(r['label']=='phishing')])
    a = np.asarray(data, dtype=float)
    matrix = []
    for i in range(len(names)):
        row = []
        for j in range(len(names)):
            row.append(float(np.corrcoef(a[:,i],a[:,j])[0,1]) if len(a)>1 and a[:,i].std()>0 and a[:,j].std()>0 else None)
        matrix.append(row)
    return dict(method='Pearson r (label correlations are point-biserial)', partition='training only',
                records=len(records), names=names, matrix=matrix)

def run_experiment(run, split, user):
    try:
        core.set_status(run,'Preprocessing')
        train, test = [core.read_csv(core.artifact(split[k])) for k in ['train','test']]
        for key in ['train','test']:
            if core.checksum(core.artifact(split[key])) != split[key+'_checksum']: raise ValueError('Split files changed; create a new split.')
        if set(map(core.fingerprint,train)) & set(map(core.fingerprint,test)): raise ValueError('Duplicate leakage detected.')
        if any(r['split_assignment']!='training' for r in train) or any(r['split_assignment']!='testing' for r in test): raise ValueError('Invalid split assignment.')
        x, xt = core.texts(train,'word'), core.texts(test,'word')
        y, yt = [r['label'] for r in train], [r['label'] for r in test]
        folds=min(5,min(Counter(y).values()))
        if folds<2: raise ValueError('At least two training records per class are required.')
        cv=StratifiedKFold(folds,shuffle=True,random_state=split['seed'])
        labels=sorted(set(y))
        if set(yt)!=set(labels): raise ValueError('Both partitions must contain every class.')
        outputs=[]
        for method in METHODS:
            core.set_status(run,'Training', {'experiment_type':'preprocessing','split':split,'current_method':method,'user':user})
            estimator=pipeline(method,split['seed'])
            started=time.perf_counter()
            scores=cross_val_score(estimator,x,y,cv=cv,scoring='f1_macro',error_score='raise')
            estimator.fit(x,y)
            duration=time.perf_counter()-started
            version=uuid.uuid4().hex
            directory=core.artifact(f'models/versions/{version}'); directory.mkdir()
            path=f'models/versions/{version}/pipeline.joblib'; joblib.dump(estimator,core.artifact(path))
            outputs.append(dict(version=version,name='Logistic Regression',feature='word',method=method,artifact=path,kind='email',
                                cross_validation_macro_f1=float(scores.mean()),cv_std=float(scores.std()),training_seconds=duration))
        # Choose before looking at test metrics; ties retain the first method.
        winner=max(outputs,key=lambda r:r['cross_validation_macro_f1'])
        predictions=[]
        for result in outputs:
            estimator=joblib.load(core.artifact(result['artifact']))
            started=time.perf_counter(); pred=estimator.predict(xt); result['testing_seconds']=time.perf_counter()-started
            report=classification_report(yt,pred,output_dict=True,zero_division=0)
            matrix=confusion_matrix(yt,pred,labels=labels).tolist()
            positive=report['phishing'] if len(labels)==2 else report['macro avg']
            result.update(accuracy=float(accuracy_score(yt,pred)),precision=positive['precision'],recall=positive['recall'],
                          f1=positive['f1-score'],macro_f1=float(f1_score(yt,pred,average='macro')),per_class=report,
                          confusion_matrix=matrix,labels=labels,false_positives=sum(p=='phishing' and t!='phishing' for t,p in zip(yt,pred)),false_negatives=sum(p!='phishing' and t=='phishing' for t,p in zip(yt,pred)),correct=int(sum(pred==np.array(yt))),incorrect=int(sum(pred!=np.array(yt))),
                          confidence_method='uncalibrated probability estimate',parameters=repr(estimator.get_params()))
            predictions.extend(dict(method=result['method'],record_id=r['record_id'],expected=truth,predicted=str(p)) for r,truth,p in zip(test,yt,pred))
            if not split.get('synthetic'):
                with core.connect() as c:
                    c.execute('INSERT INTO model_versions VALUES(?,?,?,?,?)',(result['version'],run,result['name'],result['artifact'],json.dumps(result)))
                    c.execute('INSERT INTO model_metrics VALUES(?,?)',(result['version'],json.dumps(result)))
        meta=dict(run_id=run,experiment_type='preprocessing',split=split,user=user,created_at=core.now(),models=outputs,
                  selected_method=winner['method'],selection='Highest training cross-validation macro F1; first method breaks ties',correlation=correlation(train),
                  class_distribution={'training':dict(Counter(y)),'testing':dict(Counter(yt))},model='Logistic Regression (same parameters for every method)',labels=labels,synthetic=split.get('synthetic',False))
        (core.ROOT/f'results/{run}.json').write_text(json.dumps(meta,indent=2))
        core.write_csv(core.ROOT/f'results/{run}_comparison.csv',outputs,['method','accuracy','precision','recall','f1','macro_f1','cross_validation_macro_f1','cv_std','false_positives','false_negatives','training_seconds','testing_seconds'])
        core.write_csv(core.ROOT/f'results/{run}_predictions.csv',predictions,['method','record_id','expected','predicted'])
        core.set_status(run,'Completed',meta); core.audit('preprocessing_completed',user,{'run':run})
    except Exception as e: core.set_status(run,'Failed',error=str(e))

def predict_case(meta, text, user):
    if not text.strip() or len(text)>100000: raise ValueError('Enter 1–100000 characters of email content.')
    result=next(r for r in meta['models'] if r['method']==meta['selected_method'])
    estimator=joblib.load(core.artifact(result['artifact']))
    probabilities=estimator.predict_proba([text])[0]
    case=dict(id=uuid.uuid4().hex,run_id=meta['run_id'],method=result['method'],model=result['name'],text=text,
              prediction=str(estimator.predict([text])[0]),probabilities=dict(zip(map(str,estimator.classes_),map(float,probabilities))),
              created_at=core.now(),user=user,synthetic=meta.get('synthetic',False),scope='Synthetic text-category demonstration only; not real attack detection.' if meta.get('synthetic') else 'Binary email classification. Ransomware and other attack types are not trained labels.')
    (core.ROOT/f"results/{case['id']}_new_case.json").write_text(json.dumps(case,indent=2))
    core.audit('preprocessing_new_case',user,{'case':case['id'],'run':meta['run_id']})
    return case
