<#
.SYNOPSIS
    Burns a moving "user" / "session" watermark into a source video using FFmpeg.

.DESCRIPTION
    Creates a hard, moving forensic watermark you can apply BEFORE uploading especially
    sensitive videos to Bunny. This is a static deterrent — it does NOT replace the
    server-side per-session overlay watermark in the player.

.EXAMPLE
    .\watermark.ps1 -Input .\source.mp4 -Output .\source.wm.mp4 -Text "INTERNAL ONLY"
#>
param(
    [Parameter(Mandatory)] [string]$Input,
    [Parameter(Mandatory)] [string]$Output,
    [Parameter(Mandatory)] [string]$Text
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command ffmpeg -ErrorAction SilentlyContinue)) {
    throw "ffmpeg not found in PATH. Install from https://ffmpeg.org/download.html"
}

# Drift watermark across the frame using sin/cos to make it harder to crop out.
$filter = "drawtext=text='${Text}':fontcolor=white@0.32:fontsize=h/22:" +
          "x='if(eq(mod(t\,8)\,0)\,0\,(w-text_w)*(0.5+0.4*sin(2*PI*t/40)))':" +
          "y='(h-text_h)*(0.5+0.4*cos(2*PI*t/55))':" +
          "shadowcolor=black@0.6:shadowx=2:shadowy=2"

ffmpeg -y -i "$Input" -vf $filter -c:v libx264 -preset medium -crf 20 -c:a copy "$Output"
Write-Host "Wrote $Output" -ForegroundColor Green
