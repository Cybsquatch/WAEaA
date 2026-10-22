<#
.SYNOPSIS
    Builds every WAEaA collector binary into .\dist.

.DESCRIPTION
    Produces:
      waeaa.exe                (Windows x64, latest Go - Win10/11, Server 2016+)
      waeaa-legacy.exe         (Windows x64, Go 1.20  - Win7/8/8.1, Server 2008R2/2012)
      waeaa-legacy-x86.exe     (Windows x86, Go 1.20  - 32-bit Win7)
      waeaa-linux-amd64        (static, CGO disabled)
      waeaa-linux-arm64        (static, CGO disabled)

    The legacy toolchain is installed with:
      go install golang.org/dl/go1.20.14@latest; go1.20.14 download

.PARAMETER Version
    Semantic version embedded in the binaries (default: 0.1.0-dev).
#>
param(
    [string]$Version = "0.1.0-dev",
    [string]$LegacyGo = "go1.20.14"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$commit = (git -C $root rev-parse --short HEAD 2>$null)
if (-not $commit) { $commit = "unknown" }
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$pkg = "github.com/Cybsquatch/WAEaA/collector/internal/version"

function Build([string]$goCmd, [string]$goos, [string]$goarch, [string]$flavor, [string]$out) {
    $ldflags = "-s -w -X $pkg.Version=$Version -X $pkg.Commit=$commit -X $pkg.BuildDate=$date -X $pkg.Flavor=$flavor"
    $env:GOOS = $goos; $env:GOARCH = $goarch; $env:CGO_ENABLED = "0"
    # GOTOOLCHAIN=local prevents the modern go command from auto-switching.
    $env:GOTOOLCHAIN = "local"
    Write-Host "==> $out ($goCmd $goos/$goarch, $flavor)"
    Push-Location (Join-Path $root "collector")
    try {
        & $goCmd build -trimpath -ldflags $ldflags -o (Join-Path $dist $out) ./cmd/waeaa
        if ($LASTEXITCODE -ne 0) { throw "build failed: $out" }
    } finally { Pop-Location }
}

Build "go"      "windows" "amd64" "modern" "waeaa.exe"
Build $LegacyGo "windows" "amd64" "legacy" "waeaa-legacy.exe"
Build $LegacyGo "windows" "386"   "legacy" "waeaa-legacy-x86.exe"
Build "go"      "linux"   "amd64" "modern" "waeaa-linux-amd64"
Build "go"      "linux"   "arm64" "modern" "waeaa-linux-arm64"

# SHA-256 of every release binary: recorded later in the chain of custody.
Get-ChildItem $dist -File | Where-Object { $_.Name -notlike "*.sha256" } | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$h  $($_.Name)" | Set-Content -Encoding ascii "$($_.FullName).sha256"
}
Write-Host "Done: $dist"
