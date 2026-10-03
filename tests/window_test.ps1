param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$ListFile,
  [int]$HttpPort = 18462,
  [int]$ApiPort = 18463
)
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WV {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  public static IntPtr Find(uint pid) {
    IntPtr f = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var sb = new StringBuilder(256); GetWindowTextW(h, sb, 256);
      if (sb.ToString() == "ESPECTRO PROXY PRO") { f = h; return false; }
      return true;
    }, IntPtr.Zero);
    return f;
  }
}
'@
function Count-Orphans {
  @(Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" |
    Where-Object { -not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue) }).Count
}
$fail = 0

# fase 1: ventana nativa abre y cierra limpia
$out1 = Join-Path $env:TEMP "opencode\win1.out"
$p = Start-Process -FilePath $Exe -ArgumentList $ListFile, "--http-port", $HttpPort, "--api-port", $ApiPort, "--check-interval", "0", "--window" -PassThru -RedirectStandardOutput $out1
Start-Sleep -Seconds 5
$h = [WV]::Find([uint32]$p.Id)
if ($h -eq [IntPtr]::Zero) { Write-Host "FAIL: ventana nativa no aparecio"; $fail++ } else { Write-Host "PASS: ventana nativa creada" }
if ($h -ne [IntPtr]::Zero) { [WV]::PostMessage($h, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null }
$exited = $p.WaitForExit(15000)
if (-not $exited) { Write-Host "FAIL: la ventana no cerro el proceso"; $fail++; Stop-Process -Id $p.Id -Force }
$msg = ""
if (Test-Path $out1) { $msg = Get-Content -Raw $out1 }
if ($msg -match "ventana cerrada") { Write-Host "PASS: mensaje de cierre" } else { Write-Host "FAIL: sin mensaje 'ventana cerrada'"; $fail++ }
Start-Sleep -Seconds 2
$orph = Count-Orphans
if ($orph -eq 0) { Write-Host "PASS: 0 webviews huerfanos" } else { Write-Host "FAIL: $orph webviews huerfanos"; $fail++ }

# fase 2: --window --no-browser no debe abrir ventana
$p2 = Start-Process -FilePath $Exe -ArgumentList $ListFile, "--http-port", ($HttpPort + 2), "--api-port", ($ApiPort + 2), "--check-interval", "0", "--window", "--no-browser" -PassThru
Start-Sleep -Seconds 4
$h2 = [WV]::Find([uint32]$p2.Id)
if ($h2 -eq [IntPtr]::Zero) { Write-Host "PASS: --no-browser no abre ventana" } else { Write-Host "FAIL: ventana abierta pese a --no-browser"; $fail++; [WV]::PostMessage($h2, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null }
if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force }
$p2.WaitForExit(5000)

exit $fail
