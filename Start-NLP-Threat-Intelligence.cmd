@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 goto failure
  ".venv\Scripts\python.exe" -m pip --cache-dir .pip-cache install -r requirements-lock.txt
  if errorlevel 1 goto failure
)
".venv\Scripts\python.exe" setup_models.py
if errorlevel 1 goto failure
echo Open http://127.0.0.1:5000/lab/ in your browser.
".venv\Scripts\python.exe" run.py
goto end
:failure
echo Setup failed. Review the error above and the README installation commands.
pause
:end
