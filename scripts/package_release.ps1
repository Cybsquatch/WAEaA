<#
.SYNOPSIS
    Packages built release binaries into distributable archives with checksums.
#>
param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$releaseDir = Join-Path $dist "release"
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

$docs = @(
    (Join-Path $root "README.md"),
    (Join-Path $root "LICENSE"),
    (Join-Path $root "THIRD_PARTY_NOTICES.md")
)

function Package-Zip([string]$binRelativePath, [string]$zipName) {
    $binPath = Join-Path $dist $binRelativePath
    if (-not (Test-Path $binPath)) {
        Write-Warning "Binary not found: $binRelativePath"
        return
    }
    $targetZip = Join-Path $releaseDir $zipName
    if (Test-Path $targetZip) { Remove-Item $targetZip -Force }

    $baseName = [System.IO.Path]::GetFileName($binRelativePath)
    $tempFolder = Join-Path $dist "tmp_$baseName"
    New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null
    Copy-Item $binPath -Destination (Join-Path $tempFolder $baseName)
    foreach ($doc in $docs) {
        if (Test-Path $doc) { Copy-Item $doc -Destination $tempFolder }
    }
    Compress-Archive -Path "$tempFolder\*" -DestinationPath $targetZip -CompressionLevel Optimal
    Remove-Item $tempFolder -Recurse -Force
    Write-Host "Created $targetZip"
}

function Package-TarGz([string]$binRelativePath, [string]$tarName) {
    $binPath = Join-Path $dist $binRelativePath
    if (-not (Test-Path $binPath)) {
        Write-Warning "Binary not found: $binRelativePath"
        return
    }
    $targetTar = Join-Path $releaseDir $tarName
    if (Test-Path $targetTar) { Remove-Item $targetTar -Force }

    $baseName = [System.IO.Path]::GetFileName($binRelativePath)
    $tempFolder = Join-Path $dist "tmp_$baseName"
    New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null
    Copy-Item $binPath -Destination (Join-Path $tempFolder $baseName)
    foreach ($doc in $docs) {
        if (Test-Path $doc) { Copy-Item $doc -Destination $tempFolder }
    }
    & tar.exe -czf $targetTar -C $tempFolder .
    Remove-Item $tempFolder -Recurse -Force
    Write-Host "Created $targetTar"
}

Package-Zip "waeaa.exe" "waeaa-v$Version-windows-amd64.zip"
Package-Zip "waeaa-legacy.exe" "waeaa-v$Version-windows-legacy-amd64.zip"
Package-Zip "waeaa-legacy-x86.exe" "waeaa-v$Version-windows-legacy-x86.zip"
Package-TarGz "waeaa-linux-amd64" "waeaa-v$Version-linux-amd64.tar.gz"
Package-TarGz "waeaa-linux-arm64" "waeaa-v$Version-linux-arm64.tar.gz"
Package-Zip "ingestor\waeaa-ingestor.exe" "waeaa-ingestor-v$Version-windows-amd64.zip"

# Compute SHA256 checksums of release packages
$checksums = @()
Get-ChildItem $releaseDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $checksums += "$h  $($_.Name)"
}
$checksumFile = Join-Path $releaseDir "SHA256SUMS.txt"
$checksums | Set-Content -Encoding ascii $checksumFile
Write-Host "Checksums written to $checksumFile"
