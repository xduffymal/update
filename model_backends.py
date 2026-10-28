"""Learned-embedding LSTM and pretrained BERT contextual-feature classifiers."""
import importlib.util
import json
import os
import random
import re
from pathlib import Path
from collections import Counter
import numpy as np

MAX_LENGTH=128

def checkpoint_path(name):
    value=os.environ.get('CTI_BERT_CHECKPOINT' if name=='CTI-BERT' else 'BERT_CHECKPOINT')
    return Path(value) if value else Path(__file__).resolve().parent/'models'/'checkpoints'/name.lower()

def availability():
    ready=importlib.util.find_spec('torch') is not None
    result={'LSTM':{'ready':ready,'message':'Ready' if ready else 'Install torch'}}
    for name in ['BERT','CTI-BERT']:
        p=checkpoint_path(name)
        available=ready and importlib.util.find_spec('transformers') is not None and (p/'config.json').exists() and any((p/f).exists() for f in ['model.safetensors','pytorch_model.bin'])
        result[name]={'ready':available,'message':'Ready: pretrained contextual encoder' if available else 'Run model setup to download official weights','checkpoint':str(p)}
    return result

def configure(seed):
    try: import torch
    except ImportError: raise ValueError('PyTorch is unavailable. Install requirements-transformer.txt or choose TF-IDF models.')
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed); torch.set_num_threads(2); torch.use_deterministic_algorithms(True)
    return torch

class NeuralModel:
    def __init__(self,model,vocabulary):
        self.model=model; self.vocabulary=vocabulary; self.classes_=np.array(['legitimate','phishing'])
    def inputs(self,texts):
        import torch
        rows=[]
        for s in texts:
            tokens=re.findall(r'\w+',s.lower())[:MAX_LENGTH]
            rows.append([self.vocabulary.get(t,1) for t in tokens]+[0]*(MAX_LENGTH-len(tokens)))
        return torch.tensor(rows,dtype=torch.long)
    def predict_proba(self,texts):
        import torch
        self.model.eval(); batches=[]
        with torch.inference_mode():
            for start in range(0,len(texts),8): batches.append(torch.softmax(self.model(self.inputs(texts[start:start+8])),dim=1).numpy())
        return np.concatenate(batches) if batches else np.empty((0,2))
    def predict(self,texts): return self.classes_[self.predict_proba(texts).argmax(axis=1)]

class ContextualModel:
    """Frozen pretrained encoder, supervised head; does not claim full fine-tuning."""
    def __init__(self,encoder,tokenizer,classifier=None):
        self.encoder=encoder; self.tokenizer=tokenizer; self.classifier=classifier; self.classes_=np.array(['legitimate','phishing'])
    def transform(self,texts,progress=None):
        import torch
        self.encoder.eval(); batches=[]
        with torch.inference_mode():
            for start in range(0,len(texts),8):
                encoded=self.tokenizer(texts[start:start+8],padding=True,truncation=True,max_length=MAX_LENGTH,return_tensors='pt')
                hidden=self.encoder(**encoded).last_hidden_state; mask=encoded['attention_mask'].unsqueeze(-1).float()
                batches.append(((hidden*mask).sum(dim=1)/mask.sum(dim=1).clamp(min=1)).numpy())
                if progress: progress(min(start+8,len(texts)),len(texts))
        return np.concatenate(batches) if batches else np.empty((0,self.encoder.config.hidden_size))
    def predict_proba(self,texts): return self.classifier.predict_proba(self.transform(texts))
    def predict(self,texts): return self.classes_[self.predict_proba(texts).argmax(axis=1)]

def train_neural(texts,labels,name,seed,progress=None):
    torch=configure(seed)
    if name not in {'LSTM','BERT','CTI-BERT'}: raise ValueError('Unknown neural model.')
    if name=='LSTM':
        counts=Counter(t for s in texts for t in re.findall(r'\w+',s.lower())); vocabulary={t:i+2 for i,(t,_) in enumerate(counts.most_common(20000))}
        model=TorchLSTM(len(vocabulary)+2); wrapped=NeuralModel(model,vocabulary)
        optimizer=torch.optim.AdamW(model.parameters(),lr=0.001); targets=torch.tensor([int(y=='phishing') for y in labels]); model.train()
        steps=3*((len(texts)+7)//8); completed=0
        for epoch in range(3):
            order=np.random.default_rng(seed+epoch).permutation(len(texts))
            for start in range(0,len(texts),8):
                ids=order[start:start+8]; x=wrapped.inputs([texts[i] for i in ids]); y=targets[ids]
                optimizer.zero_grad(); loss=torch.nn.functional.cross_entropy(model(x),y); loss.backward(); optimizer.step(); completed+=1
                if progress: progress(completed,steps)
        return wrapped,{'training_mode':'learned embeddings + LSTM','embedding_dimensions':64,'hidden_size':64,'epochs':3,'batch_size':8,'seed':seed,'max_length':MAX_LENGTH,'learning_rate':0.001,'confidence':'uncalibrated softmax'}
    try: from transformers import AutoTokenizer,AutoModel
    except ImportError: raise ValueError('Transformers is unavailable. Install requirements-transformer.txt.')
    p=checkpoint_path(name)
    if not availability()[name]['ready']: raise ValueError(f'{name} checkpoint missing. Run setup_models.py or use model setup in the GUI.')
    tokenizer=AutoTokenizer.from_pretrained(str(p),local_files_only=True,trust_remote_code=False)
    encoder=AutoModel.from_pretrained(str(p),local_files_only=True,trust_remote_code=False,add_pooling_layer=False)
    for parameter in encoder.parameters(): parameter.requires_grad=False
    wrapped=ContextualModel(encoder,tokenizer); features=wrapped.transform(texts,progress)
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score,StratifiedKFold
    classifier=LogisticRegression(max_iter=1000,random_state=seed); classifier.fit(features,labels); wrapped.classifier=classifier; wrapped.classes_=classifier.classes_
    manifest=json.loads((p/'checkpoint_manifest.json').read_text()) if (p/'checkpoint_manifest.json').exists() else {'checkpoint':str(p)}
    folds=min(3,min(Counter(labels).values()))
    cv=float(cross_val_score(LogisticRegression(max_iter=1000,random_state=seed),features,labels,cv=StratifiedKFold(folds,shuffle=True,random_state=seed),scoring='f1_macro').mean()) if folds>=2 else None
    return wrapped,{'training_mode':'frozen pretrained contextual encoder + trained Logistic Regression head','checkpoint':str(p),'checkpoint_manifest':manifest,'seed':seed,'max_length':MAX_LENGTH,'batch_size':8,'head_parameters':classifier.get_params(),'cross_validation_macro_f1':cv,'confidence':'head probability estimate; calibration not guaranteed'}

try:
    import torch
    class TorchLSTM(torch.nn.Module):
        def __init__(self,size):
            super().__init__(); self.embedding=torch.nn.Embedding(size,64,padding_idx=0); self.lstm=torch.nn.LSTM(64,64,batch_first=True); self.output=torch.nn.Linear(64,2)
        def forward(self,x):
            lengths=(x!=0).sum(dim=1).clamp(min=1)
            packed=torch.nn.utils.rnn.pack_padded_sequence(self.embedding(x),lengths.cpu(),batch_first=True,enforce_sorted=False)
            _,(hidden,_)=self.lstm(packed)
            return self.output(hidden[-1])
except ImportError:
    pass
