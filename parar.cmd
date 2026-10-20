@echo off
REM ============================================================
REM  ESPECTRO PROXY PRO - parar el gateway de forma limpia
REM  Cierra el proceso por PID (no por nombre: puede haber mas de
REM  una instancia) y comprueba que los puertos quedan libres.
REM ============================================================
setlocal
cd /d "%~dp0"

set "PROG=ProxyGateway.exe"
set "PIDS="

for /f "tokens=2 delims=," %%p in ('wmic process where "name='%PROG%'" get processid^,name /format:csv 2^>nul ^| find "%PROG%"') do (
  set "PIDS=!PIDS! %%~p"
)
if not defined PIDS (
  for /f "tokens=2" %%p in ('tasklist /FI "IMAGENAME eq %PROG%" /NH 2^>nul ^| find "%PROG%"') do (
    set "PIDS=!PIDS! %%p"
  )
)

if not defined PIDS (
  echo [parar] No hay ninguna instancia de %PROG% en marcha.
  endlocal
  exit /b 0
)

echo [parar] Cerrando: %PIDS%
for %%p in (%PIDS%) do taskkill /PID %%p /T /F >nul 2>&1
timeout /t 2 /nobreak >nul
echo [parar] Hecho. Puertos 8081/8082/823 libres.
endlocal
