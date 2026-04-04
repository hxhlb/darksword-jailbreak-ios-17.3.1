@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title DarkSword Panic Logs

set "TOOLS=C:\Users\smolk\Documents\palera1n-windows"
set "LOGDIR=C:\Users\smolk\Documents\palera1n-windows\Dopamine_darksword\log"

:: Метка времени через powershell (надёжнее wmic)
for /f %%A in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HH-mm-ss"') do set "STAMP=%%A"
set "CRASHDIR=%LOGDIR%\panics_!STAMP!"

if not exist "%LOGDIR%" mkdir "%LOGDIR%"
mkdir "!CRASHDIR!" 2>nul

echo ============================================
echo  DarkSword Panic Log Collector
echo  Папка: !CRASHDIR!
echo ============================================
echo.

echo [1/2] Скачиваю panic/crash логи с устройства...
echo.

"%TOOLS%\idevicecrashreport.exe" -k -e "!CRASHDIR!"

if !errorlevel! neq 0 (
    echo.
    echo [!] Ошибка: устройство не подключено или нет новых логов.
    echo     Убедитесь что iPad подключён по USB.
    echo.
    pause
    exit /b 1
)

echo.
echo [2/2] Ищу panic логи...
echo.

set "COUNT=0"
for /f %%F in ('dir /b /s "!CRASHDIR!\panic-full-*.ips" 2^>nul ^| find /c /v ""') do set "COUNT=%%F"

echo.
if !COUNT! equ 0 (
    echo Panic логов не найдено. Возможно устройство не паниковало
    echo или логи уже были скачаны ранее.
) else (
    echo Найдено panic логов: !COUNT!
)

echo.
echo Все файлы в: !CRASHDIR!
dir /b "!CRASHDIR!\panic-full-*" 2>nul
echo.
echo ============================================
pause
