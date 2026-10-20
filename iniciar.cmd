@echo off
REM ============================================================
REM  ESPECTRO PROXY PRO - arranque de produccion
REM  Doble-click: levanta el gateway con los flags de produccion
REM  (proxy en 8082 y 823, panel/API en 8081, validacion por
REM   tunel CONNECT para OpenBullet/SilverBullet).
REM ============================================================
setlocal
cd /d "%~dp0"

set "EXE=%~dp0ProxyGateway.exe"
set "LISTA=proxies.txt"
set "PUERTOS=8082,823"
set "API=8081"

if not exist "%EXE%" (
  echo [ERROR] No encuentro %EXE%
  echo         Compila con:  go build -trimpath -ldflags "-s -w" -o ProxyGateway.exe .
  pause
  exit /b 1
)

if not exist "%LISTA%" (
  echo [AVISO] No existe %LISTA% en esta carpeta.
  echo         El gateway creara una plantilla vacia.
)

REM --- 1) Afinar el stack TCP de Windows (solo la PRIMERA vez) ---
REM     Abre ~64k puertos de usar y tirar y baja TIME_WAIT de 120 s a 30 s:
REM     es lo que permite a OB/SilverBullet abrir 300+ conexiones sin
REM     agotar los puertos ("address already in use").
REM     Requiere administrador (UAC). Se puede saltar con SKIP_TUNING=1.
if /I not "%SKIP_TUNING%"=="1" (
  netsh int ipv4 show dynamicport tcp | find "1025" >nul 2>&1
  if errorlevel 1 (
    echo [tuning] Afinando el stack TCP de Windows ^(pide administrador^)... 
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList 'TUNING' -Verb RunAs -Wait" >nul 2>&1
    if errorlevel 1 (
      echo [tuning] No se pudo aplicar ^(hacia falta administrador^). Continua igual.
    ) else (
      echo [tuning] Stack TCP afinado.
    )
  ) else (
    echo [tuning] Stack TCP ya afinado.
  )
)

REM --- 2) Levantar el gateway ---
echo [gateway] Iniciando ESPECTRO PROXY PRO...
echo [gateway] Proxy: 127.0.0.1:8082 y 127.0.0.1:823
echo [gateway] Panel: http://127.0.0.1:%API%/panel
start "" "%EXE%" %LISTA% --http-port %PUERTOS% --api-port %API% --check-connect --check-interval 60 --strategy round-robin
echo [gateway] Lanzado. El panel se abre en unos segundos.
endlocal
