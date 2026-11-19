@echo off
rem Runs the full AI practice check and writes a log to runs\claude_log.txt
cd /d "%~dp0..\.."
set PYTHONUNBUFFERED=1
if not exist runs mkdir runs
set LOG=runs\claude_log.txt
echo === start %date% %time% > %LOG%
python --version >> %LOG% 2>&1
set OLLAMA=ollama
where ollama >> %LOG% 2>&1
if errorlevel 1 if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" set OLLAMA="%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
if "%OLLAMA%"=="ollama" where ollama > nul 2>&1
if errorlevel 1 if "%OLLAMA%"=="ollama" (
  echo OLLAMA_MISSING >> %LOG%
  echo Ollama is not installed. Install it from ollama.com, then run this again.
  pause
  goto :eof
)
echo === getting the AI model (first time can take several minutes) >> %LOG%
echo using %OLLAMA% >> %LOG%
%OLLAMA% pull llama3.2 >> %LOG% 2>&1
echo === starting practice bot >> %LOG%
start "AI practice bot - leave open" cmd /k python demo\ai_bot.py
timeout /t 5 /nobreak > nul
echo === running check >> %LOG%
python -m aicheck run --config demo\ai_demo.yaml --out runs\ai >> %LOG% 2>&1
echo === done %date% %time% >> %LOG%
if exist runs\ai\report.html start "" runs\ai\report.html
