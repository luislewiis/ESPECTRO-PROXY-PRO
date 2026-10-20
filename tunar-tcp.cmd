@echo off
REM ============================================================
REM  ESPECTRO PROXY PRO - afinar el stack TCP de Windows
REM  NECESITA ADMINISTRADOR (UAC). Afecta a TODO Windows, no solo
REM  al gateway, y se queda hasta que se deshaga.
REM
REM  Que hace y por que (300+ bots de OpenBullet a la vez):
REM   1) puertos de usar y tirar: ~16k -> 64.510
REM      (netsh int ipv4 set dynamicport tcp start=1025 num=64510)
REM      Con miles de conexiones por minuto, el rango por defecto se
REM      agota y aparecen errores de "address already in use".
REM   2) TIME_WAIT: 120 s -> 30 s
REM      Cada socket cerrado aguanta 2 min en TIME_WAIT; bajarlo a
REM      30 s recicla los puertos 4x mas rapido.
REM   3) MaxUserPort: 65534
REM      Coherencia con el rango ampliado.
REM
REM  Uso: doble-click (pedira permisos) o  ProxyGateway.exe --tune-tcp
REM ============================================================
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo [tuning] Se necesitan permisos de administrador: reintentando con UAC...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  endlocal
  exit /b 0
)

echo [tuning] 1/3 puertos dinamicos -> 1025-65535
netsh int ipv4 set dynamicport tcp start=1025 num=64510
echo [tuning] 2/3 TIME_WAIT -> 30 s
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f
echo [tuning] 3/3 MaxUserPort -> 65534
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f
echo [tuning] Listo. Los cambios se aplican al reiniciar los adaptadores de red.
pause
endlocal
