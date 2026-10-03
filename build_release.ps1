# Build de release ESPECTRO PROXY PRO
#   .\build_release.ps1 -Version 1.0.0
# Con 'garble' instalado (go install mvdan.cc/garble@latest) el binario sale
# ofuscado (-literals -tiny -seed=random): simbolos y literales cifrados.
# garble exige un GOROOT de SDK real (no el toolchain de GOMODCACHE): si no
# existe, descarga el SDK oficial a %USERPROFILE%\sdk\go<ver> y lo usa.
# Sin garble, build estandar con -s -w (sin symtab ni dwarf).
param(
    [string]$Version = "dev",
    [string]$BuildDate = (Get-Date -Format 'yyyy-MM-dd')
)
$ErrorActionPreference = "Stop"
$ld = "-s -w -X main.version=$Version -X main.buildDate=$BuildDate"

if (Get-Command garble -ErrorAction SilentlyContinue) {
    $goLine = (Select-String -Path go.mod -Pattern '^go\s+([\d.]+)').Matches[0].Groups[1].Value
    $sdk = "$env:USERPROFILE\sdk\go$goLine"
    if (-not (Test-Path "$sdk\bin\go.exe")) {
        Write-Host "[release] descargando SDK go$goLine a $sdk ..."
        $zip = "$env:TEMP\go$goLine.zip"
        curl.exe -L --retry 3 -C - -o $zip "https://go.dev/dl/go$goLine.windows-amd64.zip"
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $tmp = "$env:TEMP\gosdk_tmp"
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        if (Test-Path $sdk) { Remove-Item $sdk -Recurse -Force }
        New-Item -ItemType Directory -Force -Path (Split-Path $sdk) | Out-Null
        Move-Item "$tmp\go" $sdk
        Remove-Item $zip -Force
    }
    $env:GOROOT = $sdk
    $env:GOTOOLCHAIN = "local"
    $env:PATH = "$sdk\bin;$env:PATH"
    Write-Host "[release] garble + GOROOT=$sdk -> build ofuscado (version $Version)"
    garble -literals -tiny -seed=random build -trimpath -ldflags $ld -o ProxyGateway.exe .
} else {
    Write-Host "[release] garble NO instalado -> build estandar (version $Version)"
    Write-Host "[release]   para ofuscar: go install mvdan.cc/garble@latest"
    go build -trimpath -ldflags $ld -o ProxyGateway.exe .
}

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "`n[release] verificacion:"
.\ProxyGateway.exe --version
