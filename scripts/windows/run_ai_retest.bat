@echo off
rem Restarts the AI practice bot with its mistakes fixed, then retests the earlier findings.
cd /d "%~dp0..\.."
set PYTHONUNBUFFERED=1
set LOG=runs\claude_retest_log.txt
echo === start %date% %time% > %LOG%
echo === stopping any bot already using port 8788 >> %LOG%
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8788" ^| findstr "LISTENING"') do taskkill /pid %%p /f >> %LOG% 2>&1
timeout /t 3 /nobreak > nul
netstat -ano | findstr ":8788" | findstr "LISTENING" > nul && (echo PORT_STILL_BUSY >> %LOG% & goto :eof)
start "AI practice bot FIXED - leave open" cmd /k "set AI_FIXED=memory,agency,leak,indirect,cost,output&& python demo\ai_bot.py"
timeout /t 5 /nobreak > nul
echo === retesting >> %LOG%
python -m aicheck retest --config demo\ai_demo.yaml --results runs\ai\results.json >> %LOG% 2>&1
echo === done %date% %time% >> %LOG%
if exist runs\ai\retest.html start "" runs\ai\retest.html
