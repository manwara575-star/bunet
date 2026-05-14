#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Security leak gate: scans shipped frontend assets for accidental raw video URLs.

.DESCRIPTION
  Recursively searches src/VideoSecurity.Web/wwwroot/ and src/VideoSecurity.Web/Views/
    for .cshtml, .js, .ts, .css, .json files containing any of:
    \.m3u8
    \.mpd
        \.mp4
    b-cdn.net
    iframe.mediadelivery.net

  All such URLs must remain server-side (.cs only - e.g. SecurityHeadersMiddleware.cs),
  never in user-shipped assets. Exits 1 on any match.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $RepoRoot = (Resolve-Path (Join-Path $scriptDir '..')).Path
}

$scanRoots = @(
    (Join-Path $RepoRoot 'src/VideoSecurity.Web/wwwroot'),
    (Join-Path $RepoRoot 'src/VideoSecurity.Web/Views')
)

$pattern = '\.m3u8|\.mpd|\.mp4|b-cdn\.net|iframe\.mediadelivery\.net'
$includes = @('*.cshtml', '*.js', '*.ts', '*.css', '*.json')

$existingRoots = $scanRoots | Where-Object { Test-Path $_ }
if (-not $existingRoots) {
    Write-Host "check-no-raw-urls: no scan roots exist; nothing to check."
    exit 0
}

$files = foreach ($root in $existingRoots) {
    Get-ChildItem -Path $root -Recurse -File -Include $includes -ErrorAction SilentlyContinue
}

if (-not $files) {
    Write-Host "check-no-raw-urls: no candidate files under scan roots."
    exit 0
}

$hits = $files | Select-String -Pattern $pattern -CaseSensitive:$false

if ($hits) {
    Write-Host "SECURITY LEAK GATE: raw video URL pattern(s) found in shipped frontend assets:" -ForegroundColor Red
    foreach ($m in $hits) {
        $rel = Resolve-Path -LiteralPath $m.Path -Relative
        Write-Host ("  {0}:{1}: {2}" -f $rel, $m.LineNumber, $m.Line.Trim()) -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "These URLs must stay server-side (e.g. SecurityHeadersMiddleware.cs)." -ForegroundColor Red
    exit 1
}

Write-Host "check-no-raw-urls: OK - no raw video URLs found in shipped frontend assets." -ForegroundColor Green
exit 0
