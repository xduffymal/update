import csv
import io
import json
import secrets
import threading
import uuid
from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import generate_password_hash
import lab_core as core

bp=Blueprint('lab',__name__,url_prefix='/lab')
jobs_lock=threading.Lock()

def can(action):
    role=session.get('role','').lower().replace('_',' ')
    rank={'analyst':1,'senior analyst':2,'administrator':3,'admin':3}.get(role,0)
    return rank>=({'train':2,'deploy':2,'review':2,'export':2,'rollback':3,'users':3}.get(action,1))

def require(action='scan'):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            if 'user_id' not in session: return redirect(url_for('login'))
            if not can(action): abort(403,description='Your role does not permit this action.')
            return fn(*a,**kw)
        return wrapped
    return deco

def render(page,**kw):
    return render_template('lab.html',page=page,compat=core.COMPAT,**kw)

def active_models():
    versions={r['id']:json.loads(r['metadata']) for r in core.rows('model_versions')}
    return [dict(r,metrics=versions.get(r['version'],{})) for r in core.rows('deployed_models')]

def uploaded():
    files=request.files.getlist('files')
    if len(files)>50: raise ValueError('Upload at most 50 files per batch.')
    result=[(f.filename,f.read(8*1024*1024+1)) for f in files if f.filename]
    if not result: raise ValueError('Choose at least one file.')
    return result

@bp.route('/setup',methods=['GET','POST'])
def setup():
    with core.connect() as c:
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]: return redirect(url_for('login'))
        if request.method=='POST':
            username=request.form.get('username','').strip(); password=request.form.get('password','')
            if not username or len(password)<12: raise ValueError('Choose a username and password with at least 12 characters.')
            c.execute('INSERT INTO users(username,password,role,access_level) VALUES(?,?,?,?)',(username,generate_password_hash(password),'administrator',3))
            flash('Administrator created. Log in to continue.'); return redirect(url_for('login'))
    return render('setup')

@bp.route('/')
@require()
def dashboard():
    imports=[json.loads(r['metadata']) for r in core.rows('dataset_imports')]
    scans=[json.loads(r['result']) for r in core.rows('email_scans')]
    versions=[json.loads(r['metadata']) for r in core.rows('model_versions')]
    return render('dashboard',imports=imports,scans=scans,versions=versions,active=active_models(),runs=core.rows('training_runs'),splits=core.splits())

@bp.route('/collection',methods=['GET','POST'])
@require()
def collection():
    pending=core.ROOT/'data/raw'/f"{session['user_id']}_draft.json"
    records=json.loads(pending.read_text()) if pending.exists() else []
    if request.method=='POST':
        action=request.form.get('action')
        if action=='import':
            field_map={key:request.form.get(key+'_column','').strip() for key in ['body','label','subject']}
            new=core.collect(uploaded(),request.form.get('source',''),request.form.get('label',''),request.form.get('intended','training'),request.form.get('notes',''),request.form.get('reviewed')=='on',field_map)
            records=core.dedup(records+new)
            pending.write_text(json.dumps(records)); core.audit('import_data',session['username'],{'records':len(new),'source':request.form.get('source')})
            flash(f'Imported records. Combined preview contains {len(records)} unique records.')
        elif action=='save':
            metadata=core.save_dataset(records,session['username']); pending.unlink(missing_ok=True); flash(f"Saved {metadata['filename']}"); return redirect(url_for('lab.datasets'))
        elif action=='clear': pending.unlink(missing_ok=True); records=[]
        elif action=='online':
            from source_importer import collect_public
            new=collect_public(request.form['source_key'],int(request.form.get('limit','100')),request.form.get('intended','training'),int(request.form.get('sample_seed','42')))
            records=core.dedup(records+new); pending.write_text(json.dumps(records))
            core.audit('collect_public_source',session['username'],{'source':request.form['source_key'],'count':len(new)})
            flash(f'Collected {len(new)} real labeled records; review the combined preview before saving.')
    return render('collection',records=records)

@bp.route('/datasets',methods=['GET','POST'])
@require()
def datasets():
    imports=[json.loads(r['metadata']) for r in core.rows('dataset_imports')]
    allowed={r['filename'] for r in imports}
    chosen=request.values.get('dataset','')
    if chosen and chosen not in allowed: raise ValueError('Select a saved dataset.')
    if request.method=='POST':
        if not can('train'): abort(403)
        split=core.split_dataset(chosen,float(request.form['ratio']),int(request.form['seed']),session['username'])
        flash(f"Saved {split['train_count']} training and {split['test_count']} testing records."); return redirect(url_for('lab.training'))
    preview=core.read_csv(core.artifact(chosen)) if chosen else []
    return render('datasets',imports=imports,preview=preview,chosen=chosen,splits=core.splits())

@bp.route('/training',methods=['GET','POST'])
@require('train')
def training():
    if request.method=='POST':
        feature=request.form['feature']; names=request.form.getlist('models')
        if not names or any(n not in core.COMPAT.get(feature,[]) for n in names): raise ValueError('Choose compatible models for the selected feature method.')
        split=next((s for s in core.splits() if s['id']==request.form['split']),None)
        if split is None: raise ValueError('Choose a saved split.')
        with jobs_lock:
            with core.connect() as c:
                if c.execute("SELECT 1 FROM training_runs WHERE status IN ('Queued','Preprocessing','Training','Evaluating')").fetchone(): raise ValueError('A training job is already active. Wait for it to finish.')
                ident=uuid.uuid4().hex
                c.execute('INSERT INTO training_runs VALUES(?,?,?,?)',(ident,'Queued',json.dumps({'split':split,'feature':feature,'names':names,'user':session['username']}),None))
            threading.Thread(target=core.train_run,args=(ident,split,feature,names,session['username']),daemon=True).start()
        flash('Training queued. Refresh to see saved status and results.'); return redirect(url_for('lab.training'))
    versions=[]
    for r in core.rows('model_versions'):
        v=json.loads(r['metadata'])
        if v.get('kind')=='threat': continue
        v['run_id']=r['run_id']; versions.append(v)
    from neural_training import availability
    runs=[r for r in core.rows('training_runs') if json.loads(r['metadata'] or '{}').get('experiment_type')!='legacy_threat_reports']
    return render('training',splits=core.splits(),runs=runs,versions=versions,availability=availability())

@bp.route('/models',methods=['GET','POST'])
@require('deploy')
def models():
    if request.method=='POST':
        if request.form.get('action')=='setup':
            if not can('users'): abort(403)
            from setup_models import CHECKPOINTS,prepare
            name=request.form.get('name')
            if name not in CHECKPOINTS: raise ValueError('Unknown official checkpoint.')
            ident=uuid.uuid4().hex
            with core.connect() as c:
                if c.execute("SELECT 1 FROM system_jobs WHERE status IN ('Queued','Downloading')").fetchone(): raise ValueError('A checkpoint download is already running.')
                c.execute('INSERT INTO system_jobs VALUES(?,?,?,?)',(ident,'Queued',json.dumps({'name':name}),None))
            def download_weights():
                try:
                    def update(message,**kwargs):
                        with core.connect() as c: c.execute('UPDATE system_jobs SET status=?,metadata=? WHERE id=?',('Downloading',json.dumps({'name':name,'message':message}),ident))
                    path=prepare(name,update)
                    with core.connect() as c: c.execute('UPDATE system_jobs SET status=?,metadata=? WHERE id=?',('Completed',json.dumps({'name':name,'checkpoint':str(path)}),ident))
                except Exception as e:
                    with core.connect() as c: c.execute('UPDATE system_jobs SET status=?,error=? WHERE id=?',('Failed',str(e),ident))
            threading.Thread(target=download_weights,daemon=True).start(); core.audit('prepare_checkpoint',session['username'],{'name':name}); flash('Checkpoint preparation started. Refresh Model Management for status.')
        elif request.form.get('action')=='rollback':
            if not can('rollback'): abort(403)
            core.rollback(request.form['kind'],session['username']); flash('Previous version restored.')
        else: core.deploy(request.form['version'],session['username']); flash('Selected model deployed.')
        return redirect(url_for('lab.models'))
    from neural_training import availability
    return render('models',versions=[json.loads(r['metadata']) for r in core.rows('model_versions')],active=active_models(),availability=availability(),system_jobs=core.rows('system_jobs'))

@bp.route('/analyze',methods=['GET','POST'])
@require()
def analyze():
    results=[]
    if request.method=='POST':
        if request.form.get('body','').strip():
            results.append(core.analyze({'subject':request.form.get('subject',''),'body':request.form['body'],'sender':'','reply_to':'','headers':{},'attachments':[],'urls':[]},session['username']))
        files=request.files.getlist('files')
        if len(files)>50: raise ValueError('Upload at most 50 files.')
        for f in files:
            if not f.filename: continue
            for email in core.parse_upload(f.read(8*1024*1024+1),f.filename): results.append(core.analyze(email,session['username']))
        attachment_uploads=request.files.getlist('attachments')
        if len(attachment_uploads)>50: raise ValueError('Upload at most 50 attachments.')
        if any(f.filename for f in attachment_uploads):
            from attachment_safety import ALLOWED
            from pathlib import Path
            attachments=[]
            for f in attachment_uploads:
                if not f.filename: continue
                content=f.read(8*1024*1024+1)
                if len(content)>8*1024*1024 or Path(f.filename).suffix.lower() not in ALLOWED: raise ValueError('Unsupported attachment or attachment exceeds 8 MB.')
                attachments.append(core.attachment_info(f.filename,content,f.mimetype))
            results.append(core.analyze({'subject':'Attachment-only investigation','body':'','sender':'','reply_to':'','headers':{},'urls':[],'attachments':attachments},session['username']))
        if not results: raise ValueError('Paste an email or choose an EML, TXT or MBOX file.')
        if len(results)>1:
            with core.connect() as c: c.execute('INSERT INTO batch_jobs VALUES(?,?,?,?)',(uuid.uuid4().hex,session['username'],json.dumps([r['id'] for r in results]),core.now()))
        core.audit('email_scan',session['username'],{'count':len(results)})
    return render('analyze',results=results)

@bp.route('/history')
@require()
def history():
    return render('history',results=[json.loads(r['result']) for r in core.rows('email_scans')])

@bp.route('/feedback',methods=['POST'])
@require()
def feedback():
    label=request.form.get('label'); text=request.form.get('sanitized_text','').strip()
    if label not in {'legitimate','phishing'} or not text: raise ValueError('Choose a corrected label and explicitly supply sanitized text with private details removed.')
    with core.connect() as c:
        if not c.execute('SELECT 1 FROM email_scans WHERE id=?',(request.form['scan'],)).fetchone(): raise ValueError('Unknown scan.')
        c.execute('INSERT INTO analyst_feedback VALUES(?,?,?,?,?,?,?)',(uuid.uuid4().hex,request.form['scan'],label,text,'pending',session['username'],None))
    flash('Feedback submitted for senior review. It has not entered a training dataset.')
    return redirect(url_for('lab.history'))

@bp.route('/review',methods=['GET','POST'])
@require('review')
def review():
    if request.method=='POST':
        with core.connect() as c:
            row=c.execute("SELECT * FROM analyst_feedback WHERE id=? AND status='pending'",(request.form['id'],)).fetchone()
        if not row: raise ValueError('Feedback already processed or missing.')
        if request.form.get('action')=='approve':
            record=core.normalize({'body':row['sanitized_text'],'label':row['label']},'Approved analyst feedback','feedback',row['scan_id'],row['label'],'training','Senior analyst approved sanitized text',True)
            core.save_dataset([record],session['username']); status='approved'
        else: status='rejected'
        with core.connect() as c: c.execute('UPDATE analyst_feedback SET status=?,approver=? WHERE id=?',(status,session['username'],row['id']))
        core.audit('review_feedback',session['username'],{'id':row['id'],'status':status}); flash(f'Feedback {status}.')
    return render('review',feedback=core.rows('analyst_feedback'))

@bp.route('/download')
@require()
def download():
    file=request.args.get('file','')
    if not file.startswith(('data/','results/')) or not file.endswith(('.csv','.json')): abort(403)
    if file.startswith('results/') and not can('export'): abort(403)
    path=core.artifact(file)
    if not path.is_file(): abort(404)
    return send_file(path,as_attachment=True)

@bp.route('/export/<scan>/<format>')
@require('export')
def export(scan,format):
    with core.connect() as c: row=c.execute('SELECT result FROM email_scans WHERE id=?',(scan,)).fetchone()
    if not row: abort(404)
    result=json.loads(row[0]); buffer=io.BytesIO()
    if format=='csv':
        out=io.StringIO(); w=csv.writer(out); w.writerow(['id','classification','risk_score','email_prediction','email_confidence','recommendation','rule_score','rule_findings','url_evidence','attachment_evidence','entities','correlation']); w.writerow([result['id'],result['classification'],result['risk_score'],result['email_model']['prediction'],result['email_model']['confidence'],result['recommendation'],result['rule_score'],json.dumps(result['rule_findings']),json.dumps(result['urls']),json.dumps(result['email']['attachments']),json.dumps(result.get('entities',{})),json.dumps(result.get('correlation',{}))]); buffer.write(out.getvalue().encode('utf-8-sig')); mimetype='text/csv'
    elif format=='pdf':
        from scan_report import build_pdf
        build_pdf(buffer,result); mimetype='application/pdf'
    else: abort(404)
    buffer.seek(0); core.audit('export_scan',session['username'],{'id':scan,'format':format})
    return send_file(buffer,mimetype=mimetype,as_attachment=True,download_name=f'scan_{scan}.{format}')

@bp.route('/users',methods=['GET','POST'])
@require('users')
def users():
    if request.method=='POST':
        if request.form.get('action')=='role':
            role=request.form.get('role'); ident=int(request.form['user_id'])
            if role not in {'analyst','senior analyst','administrator'}: raise ValueError('Choose a valid role.')
            with core.connect() as c:
                previous=c.execute('SELECT username,role FROM users WHERE user_id=?',(ident,)).fetchone()
                if not previous: raise ValueError('Unknown user.')
                if previous['role'] in {'administrator','admin'} and role!='administrator' and c.execute("SELECT COUNT(*) FROM users WHERE role IN ('administrator','admin')").fetchone()[0]<=1: raise ValueError('Keep at least one administrator.')
                c.execute('UPDATE users SET role=?,access_level=? WHERE user_id=?',(role,{'analyst':1,'senior analyst':2,'administrator':3}[role],ident))
            core.audit('change_user_role',session['username'],{'username':previous['username'],'previous_role':previous['role'],'role':role})
            if ident==session['user_id']: session['role']=role
            flash('Role updated.'); return redirect(url_for('lab.users') if can('users') else url_for('lab.dashboard'))
        role=request.form['role']; username=request.form['username'].strip(); password=request.form['password']
        if role not in {'analyst','senior analyst','administrator'} or len(password)<12 or not username: raise ValueError('Provide a username, a 12-character password, and a valid role.')
        with core.connect() as c: c.execute('INSERT INTO users(username,password,role,access_level) VALUES(?,?,?,?)',(username,generate_password_hash(password),role,{'analyst':1,'senior analyst':2,'administrator':3}[role]))
        core.audit('create_user',session['username'],{'username':username,'role':role}); flash('User created.')
    return render('users',users=core.rows('users'))

@bp.route('/settings',methods=['GET','POST'])
@require()
def settings():
    from experiment_settings import get_settings,save_retention,apply_retention
    if request.method=='POST':
        if not can('users'): abort(403)
        if request.form.get('action')=='retention': save_retention(int(request.form['days']),session['username']); flash('Retention policy saved. No records removed.')
        elif request.form.get('action')=='apply_retention': flash(f'Removed {apply_retention(session["username"])} old scans after making a recoverable database snapshot. Users and model data are preserved.')
    return render('settings',settings=get_settings())

@bp.route('/threats',methods=['GET','POST'])
@require()
def threats():
    if request.method=='POST':
        from threat_workspace import collect,train
        if request.form.get('action')=='train':
            if not can('train'): abort(403)
            result=train(session['username']); flash('Threat-report version trained; deploy it separately in Model Management.')
        else:
            added=collect(request.form['source'],int(request.form.get('limit','20')),session['user_id'],session['username'],request.form.get('notes','')); flash(f'Collected {added} new threat reports. No email training data was changed.')
    return render('threats',reports=core.rows('reports'),feeds=core.rows('feed_runs'))

@bp.route('/validation',methods=['GET','POST'])
@require('train')
def validation():
    result=None
    imports=[json.loads(r['metadata']) for r in core.rows('dataset_imports')]
    files=[d for d in imports if d['filename'].startswith('data/validation/')]
    if request.method=='POST':
        filename=request.form['dataset']
        if filename not in {d['filename'] for d in files}: raise ValueError('Select a saved independent validation dataset.')
        from validation_service import evaluate
        result=evaluate(filename,request.form.getlist('versions'),session['username'])
    return render_template('validation.html',datasets=files,versions=[dict(json.loads(r['metadata']),run_id=r['run_id']) for r in core.rows('model_versions') if json.loads(r['metadata']).get('kind')!='threat'],result=result)

@bp.route('/reports')
@require('export')
def reports():
    files=[str(p.relative_to(core.ROOT)).replace('\\','/') for p in (core.ROOT/'results').glob('*') if p.suffix in {'.csv','.json'}]
    return render_template('reports.html',files=sorted(files),alerts=core.rows('email_alerts'))

@bp.route('/preprocessing',methods=['GET','POST'])
@require('train')
def preprocessing():
    from preprocessing_experiment import run_experiment, predict_case, EXAMPLE
    runs=core.rows('training_runs')
    experiments=[dict(r,data=json.loads(r['metadata'] or '{}')) for r in runs if json.loads(r['metadata'] or '{}').get('experiment_type')=='preprocessing']
    chosen=request.values.get('run','')
    selected=next((r['data'] for r in experiments if r['id']==chosen and r['status']=='Completed'),None)
    case=None
    if request.method=='POST':
        if request.form.get('action') in {'train','create_demo'}:
            if request.form.get('action')=='create_demo':
                from synthetic_attack_data import create_demo
                split=create_demo(session['username'])
            else:
                split=next((s for s in core.splits() if s['id']==request.form.get('split')),None)
            if split is None: raise ValueError('Choose a saved split.')
            with jobs_lock:
                with core.connect() as c:
                    if c.execute("SELECT 1 FROM training_runs WHERE status IN ('Queued','Preprocessing','Training','Evaluating')").fetchone(): raise ValueError('A training job is running. Wait for completion.')
                    ident=uuid.uuid4().hex
                    c.execute('INSERT INTO training_runs VALUES(?,?,?,?)',(ident,'Queued',json.dumps({'experiment_type':'preprocessing','split':split,'user':session['username']}),None))
                threading.Thread(target=run_experiment,args=(ident,split,session['username']),daemon=True).start()
            flash('Preprocessing comparison queued. Refresh to see progress.')
            return redirect(url_for('lab.preprocessing',run=ident))
        if request.form.get('action')!='predict' or selected is None: raise ValueError('Choose a completed comparison.')
        case=predict_case(selected,request.form.get('text',''),session['username'])
    return render_template('preprocessing.html',splits=core.splits(),experiments=experiments,selected=selected,case=case,example=EXAMPLE)

def register_lab(app):
    app.register_blueprint(bp)
    @app.context_processor
    def helpers():
        if 'csrf' not in session: session['csrf']=secrets.token_hex(24)
        return {'can':can,'csrf':session['csrf']}
    @app.before_request
    def protect():
        if session.get('user_id'):
            with core.connect() as c: account=c.execute('SELECT role FROM users WHERE user_id=?',(session['user_id'],)).fetchone()
            if account: session['role']=account['role']
        if request.method=='POST' and (not session.get('csrf') or not secrets.compare_digest(session.get('csrf',''),request.form.get('csrf') or request.headers.get('X-CSRF-Token',''))): abort(400,description='Invalid form token. Reload the page and try again.')
        # First-run setup uses the existing user table, never replaces users.
        if request.endpoint=='login':
            with core.connect() as c:
                if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0: return redirect(url_for('lab.setup'))
        if request.endpoint in {'analyze','run_feeds'} or (request.endpoint=='upload' and request.method=='POST'):
            import app as legacy
            if legacy.model is None:
                from threat_workspace import load_deployed
                restored=load_deployed()
                if restored is not None: legacy.model=restored.named_steps['model']; legacy.vectorizer=restored.named_steps['features']
            model=legacy.model
            if model is None: abort(503,description='The original threat-report model is unavailable. Use Analyze Email after training and deploying an email model.')
    @app.errorhandler(ValueError)
    def invalid(error):
        return render_template('error.html',message=str(error)),400
    @app.errorhandler(413)
    def oversized(error): return render_template('error.html',message='Upload exceeds the 16 MB request limit. Each file must be at most 8 MB.'),413
    import sqlite3
    @app.errorhandler(sqlite3.IntegrityError)
    def conflict(error): return render_template('error.html',message='This record conflicts with an existing record. Check for a duplicate username or invalid reference.'),400
    import requests
    @app.errorhandler(requests.RequestException)
    def network(error): return render_template('error.html',message='Public source could not be reached or its certificate could not be verified. No source records were imported. '+str(error)),400
