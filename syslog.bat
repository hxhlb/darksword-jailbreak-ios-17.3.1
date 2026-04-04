@echo off
chcp 65001 >nul
title DarkSword Syslog

set "TOOLS=C:\Users\smolk\Documents\palera1n-windows"
set "LOGDIR=C:\Users\smolk\Documents\palera1n-windows\Dopamine_darksword\log"

:: Имя файла с датой и временем
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set "DT=%%I"
set "STAMP=%DT:~0,4%-%DT:~4,2%-%DT:~6,2%_%DT:~8,2%-%DT:~10,2%-%DT:~12,2%"
set "LOGFILE=%LOGDIR%\syslog_%STAMP%.txt"

if not exist "%LOGDIR%" mkdir "%LOGDIR%"

echo ============================================
echo  DarkSword Syslog Capture
echo  Лог: %LOGFILE%
echo  Фильтр: DarkSword
echo  Нажмите Ctrl+C для остановки
echo ============================================
echo.

"%TOOLS%\idevicesyslog.exe" --match DarkSword 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath '%LOGFILE%'"
