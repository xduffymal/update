"""Fetch verified model weights/configuration only, never execute remote model code."""
import hashlib
import json
import os
from pathlib import Path
import requests
import truststore
truststore.inject_into_ssl()

CHECKPOINTS={'BERT':'google-bert/bert-base-uncased','CTI-BERT':'ibm-research/CTI-BERT'}
BASE=Path(__file__).resolve().parent/'models'/'checkpoints'

def prepare(name,progress=print):
    repo=CHECKPOINTS[name]; destination=BASE/name.lower(); destination.mkdir(parents=True,exist_ok=True)
    existing=destination/'checkpoint_manifest.json'
    previous=json.loads(existing.read_text()) if existing.exists() else None
    suffix='/revision/'+previous['revision'] if previous else ''
    response=requests.get(f'https://huggingface.co/api/models/{repo}{suffix}',timeout=30); response.raise_for_status(); info=response.json(); revision=info['sha']
    available={r['rfilename'] for r in info['siblings']}
    weight='model.safetensors' if 'model.safetensors' in available else 'pytorch_model.bin'
    wanted=[f for f in ['config.json','tokenizer.json','tokenizer_config.json','special_tokens_map.json','vocab.txt',weight] if f in available]
    if weight not in wanted: raise ValueError(f'No supported weights for {repo}')
    manifest={'name':name,'repository':repo,'revision':revision,'source':f'https://huggingface.co/{repo}','files':{}}
    for filename in wanted:
        target=destination/filename
        valid=target.exists() and (not previous or filename in previous['files'] and hashlib.sha256(target.read_bytes()).hexdigest()==previous['files'][filename]['sha256'])
        if not valid:
            progress(f'Downloading {name}: {filename}',flush=True)
            temporary=target.with_suffix(target.suffix+'.partial')
            try:
                with requests.get(f'https://huggingface.co/{repo}/resolve/{revision}/{filename}',stream=True,timeout=(30,120)) as data:
                    data.raise_for_status()
                    with temporary.open('wb') as out:
                        for chunk in data.iter_content(1024*1024): out.write(chunk)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        digest=hashlib.file_digest(target.open('rb'),'sha256').hexdigest()
        manifest['files'][filename]={'sha256':digest,'bytes':target.stat().st_size}
    (destination/'checkpoint_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    progress(f'{name} checkpoint ready: {destination}',flush=True)
    return destination

if __name__=='__main__':
    for name in CHECKPOINTS: prepare(name)
