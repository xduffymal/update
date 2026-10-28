"""Windows entry point. No legacy launcher, compatibility shims or model required."""
from database import initialize_database
import lab_core

def initialize():
    initialize_database()
    lab_core.init()
    # Interrupted in-process workers cannot resume after a restart.
    with lab_core.connect() as c:
        c.execute("UPDATE training_runs SET status='Failed',error='Server restarted before training completed; start a new run.' WHERE status IN ('Queued','Preprocessing','Training','Evaluating')")
        c.execute("UPDATE system_jobs SET status='Failed',error='Server restarted during checkpoint preparation. Run setup again.' WHERE status IN ('Queued','Downloading')")

if __name__=='__main__':
    initialize()
    from app import app
    print('Open http://127.0.0.1:5000/lab/ — first launch opens administrator setup.')
    app.run(host='127.0.0.1',port=5000,debug=False,use_reloader=False)
