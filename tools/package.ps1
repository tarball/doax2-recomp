# Builds a release for players: build\package\doax2-recomp\ and a zip of it (ANALYSIS.md, Phase 5, Packaging, The
# launcher). It holds the game's code, recompiled, and the version patch that plays the USA disc as Title Update 2, but
# none of the game's files: players bring their disc image, which the launcher checks and the game reads its files from.
#   DOAX2 Launcher.exe                     what players start (runtime/launcher/)
#   doax2.exe, doax2_ppc.dll               the game's executable and its code module (the Release build's)
#   doax2_tu2.vpatch                       what plays the USA disc as Title Update 2 (runtime/disc_image.h)
#   FFmpeg's DLLs                          its audio decoder
#   README.txt, licenses\
# It stops if anything else is in it.
# Usage: powershell -ExecutionPolicy Bypass -File tools\package.ps1 -VersionPatch <file> [-Version <name>] [-NoBuild]
#   [-NoZip]
#   -Version names the release (default: git describe): a release's is its tag in the release repository, its date,
#   time and commit (v2026.10.30.115807-f2e1697), which the README's source link names. -VersionPatch is the version
#   patch (tools\versionpatch.py's, made from the USA disc and Title Update 2's executable: game-derived, so
#   tools\release.ps1 builds it for each release, and it's never committed). Every disc needs it, since the game plays
#   Title Update 2, which is on no disc: a release without it plays nothing. -NoBuild packages the Release build as it
#   is.
param(
    [string]$Version = '',
    [string]$VersionPatch = '',
    [switch]$NoBuild,
    [switch]$NoZip
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# The game: CMakeLists.txt's GAME_TITLE, GAME_ANY_DISC (the disc players need), GAME_PREFIX, the executable and the
# launcher (GAME_LAUNCHER); the version patch's file (runtime/disc_image.cpp's other version).
$title = 'Dead or Alive Xtreme 2'
$disc = 'Dead or Alive Xtreme 2 (USA)'
$prefix = 'DOAX2'
$executable = 'doax2'
$launcher = "$prefix Launcher.exe"
$folderName = 'doax2-recomp'
$versionPatchName = "$($executable)_tu2.vpatch"
# The release repository, a commit and a tag a release, and the XenonRecomp fork.
$sourceRepository = 'https://github.com/tarball/doax2-recomp'
$xenonRepository = 'https://github.com/tarball/XenonRecomp'
$xenonUpstream = 'https://github.com/hedge-dev/XenonRecomp'

# XenonRecomp: XENONRECOMP_ROOT, else beside this checkout, else (in a worktree) beside the main checkout, as env.cmd.
# Its licenses, and those of what it puts in the game's code, go in the release.
$xenonRecomp = $env:XENONRECOMP_ROOT
if (-not $xenonRecomp) {
    $xenonRecomp = Join-Path (Split-Path $root -Parent) 'XenonRecomp'
    if (-not (Test-Path (Join-Path $xenonRecomp 'thirdparty\simde'))) {
        $common = (& git -C $root rev-parse --path-format=absolute --git-common-dir).Trim()
        $xenonRecomp = Join-Path (Split-Path (Split-Path $common -Parent) -Parent) 'XenonRecomp'
    }
}
if (-not (Test-Path (Join-Path $xenonRecomp 'LICENSE.md'))) { throw "No XenonRecomp checkout in $xenonRecomp (set XENONRECOMP_ROOT)" }
$ffmpeg = Join-Path $root 'third_party\ffmpeg'
if (-not (Test-Path (Join-Path $ffmpeg 'LICENSE.txt'))) { throw "FFmpeg isn't in $ffmpeg (run tools\getffmpeg.ps1): without it the game has no XMA audio or radio." }
if (-not $VersionPatch) { throw "Every disc plays with the version patch: give -VersionPatch <$versionPatchName> (tools\release.ps1 makes it)." }
if (-not (Test-Path -LiteralPath $VersionPatch -PathType Leaf)) { throw "There's no version patch $VersionPatch." }
$magic = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $VersionPatch).Path), 0, 4)
if ($magic -ne 'VPAT') { throw "$VersionPatch isn't a version patch." }

if (-not $NoBuild) {
    $env:XENONRECOMP_ROOT = $xenonRecomp
    & cmd.exe /c call (Join-Path $root 'build.cmd') Release
    if ($LASTEXITCODE) { throw 'The build failed.' }
}
$build = Join-Path $root 'build\Release'
$module = "$($executable)_ppc.dll"
foreach ($file in "$executable.exe", $module, $launcher) {
    if (-not (Test-Path (Join-Path $build $file))) { throw "No $file in ${build}: build.cmd Release first" }
}
# The commit (or a version tag), not the release/<name> tags that record a release's commit, whose slash a file name
# can't have.
if (-not $Version) { $Version = (& git -C $root describe --always --dirty --tags --exclude 'release/*').Trim() }
# A release's source is its tag in the release repository (the first releases' names have the date alone).
$source = if ($Version -match '^v\d{4}\.\d{2}\.\d{2}(\.\d{6})?-[0-9a-f]{7,}$') { "$sourceRepository/tree/$Version" } else { $sourceRepository }

$packages = Join-Path $root 'build\package'
$package = Join-Path $packages $folderName
if (Test-Path $package) { Remove-Item -Recurse -Force $package }
$licenses = Join-Path $package 'licenses'
New-Item -ItemType Directory -Force $licenses | Out-Null

# The launcher, the game's executable and code, and FFmpeg's DLLs: the Release build's.
$dlls = @(Get-ChildItem (Join-Path $build '*.dll') | Where-Object { $_.Name -ne $module })
Copy-Item (Join-Path $build $launcher), (Join-Path $build "$executable.exe"), (Join-Path $build $module) $package
$dlls | Copy-Item -Destination $package
$moduleHash = (Get-FileHash (Join-Path $package $module) -Algorithm SHA256).Hash.ToLowerInvariant()
# The version patch, beside the game's executable, where it looks for it.
Copy-Item -LiteralPath $VersionPatch (Join-Path $package $versionPatchName)
$patchHash = (Get-FileHash (Join-Path $package $versionPatchName) -Algorithm SHA256).Hash.ToLowerInvariant()

# Licenses: this project's, the GPL-3.0 (LICENSE), and those of what's shipped or compiled in. In doax2.exe: xxHash
# (BSD-2), and parts that follow Xenia's (BSD-3-Clause: tools\licenses\xenia.txt); in the game's code module:
# XenonRecomp's ppc_context.h (MIT) and simde (MIT); beside them: FFmpeg (LGPL). The LZMA SDK's decoder in doax2.exe and
# the launcher (third_party\lzma) is in the public domain, so it has no license to ship.
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $licenses "$folderName (GPL-3.0).txt")
$third = Join-Path $xenonRecomp 'thirdparty'
Copy-Item (Join-Path $xenonRecomp 'LICENSE.md') (Join-Path $licenses 'XenonRecomp.txt')
Copy-Item (Join-Path $third 'simde\COPYING') (Join-Path $licenses 'simde.txt')
Copy-Item (Join-Path $third 'xxHash\LICENSE') (Join-Path $licenses 'xxHash.txt')
Copy-Item (Join-Path $root 'tools\licenses\xenia.txt') (Join-Path $licenses 'Xenia.txt')
$ffmpegBuild = [regex]::Match((Get-Content -Raw (Join-Path $root 'tools\getffmpeg.ps1')), "(?m)^\`$name = '([^']+)'").Groups[1].Value
$ffmpegLicense = (Get-Content -Raw (Join-Path $ffmpeg 'LICENSE.txt')).TrimEnd()
Set-Content (Join-Path $licenses 'FFmpeg.txt') -Encoding UTF8 ("The FFmpeg DLLs are BtbN's LGPL build $ffmpegBuild " +
    "(https://github.com/BtbN/FFmpeg-Builds, which has its build scripts), from FFmpeg's source at " +
    "https://git.ffmpeg.org/ffmpeg.git. Their license:`r`n`r`n$ffmpegLicense")

$readme = @"
$title for Windows ($Version)

An unofficial Windows port of the Xbox 360 game. It doesn't include the game's files: you need your own
$disc disc image to play.

To play
1. Keep this folder somewhere you can write to, such as in Documents (not Program Files).
2. Run "$launcher". If Windows says it doesn't recognize the app, choose More info, then Run anyway.
3. Select your $disc disc image, then press Launch.

Requirements: 64-bit Windows 10 or 11, a processor with AVX, a graphics card with Direct3D 12, and about 2 GB of free
disk space.

Controls: an Xbox controller or any XInput controller (PlayStation controllers need a tool such as DS4Windows).
Keyboard: arrows or WASD move, Enter is Start, Backspace is Back, Z/J/Space is A, X/K is B, C/U is X, V/I is Y, Q and
E are the shoulder buttons, 1 and 3 the triggers.

Graphics options are in OPTIONS > Video Settings. Alt+Enter toggles fullscreen.

The first run copies 1.7 GB of the game to its hard disk cache in the background (about 7 minutes). Saves, settings
and the log ($executable.log) are in the data folder.

To update, extract a new release over this one. The data folder is kept.

Source: $source
Recompiled with a fork of XenonRecomp: $xenonRepository (XenonRecomp: $xenonUpstream)
License: GPL-3.0 (licenses\$folderName (GPL-3.0).txt). The licenses folder also has those of the libraries included.
"@
Set-Content (Join-Path $package 'README.txt') -Encoding ASCII ($readme -replace "`r?`n", "`r`n")

# Only these files: the game's code, but nothing else of the game (its data, the generated source, build files) nor of a
# player's folder.
$expected = @($launcher, "$executable.exe", $module, $versionPatchName, 'README.txt', 'licenses') + @($dlls | ForEach-Object Name)
$unexpected = @(Get-ChildItem $package | Where-Object { $expected -notcontains $_.Name })
if ($unexpected.Count) { throw "Unexpected files in the package: $($unexpected.Name -join ', ')" }
$notShipped = @(Get-ChildItem -Recurse $package | Where-Object {
    $_.Extension -in '.xex', '.pe', '.iso', '.cpp', '.obj', '.lib', '.pdb' -or
    ($_.PSIsContainer -and $_.Name -in 'ppc', 'obj', 'private', 'data', 'dumps', 'cache', 'content') })
if ($notShipped.Count) { throw "The package holds what it mustn't: $($notShipped.FullName -join ', ')" }

$files = @(Get-ChildItem -Recurse -File $package)
'{0}: {1} files, {2:N1} MB' -f $package, $files.Count, (($files | Measure-Object Length -Sum).Sum / 1MB)
$files | Group-Object { ($_.FullName.Substring($package.Length + 1) -split '\\')[0] } | ForEach-Object {
    '  {0,-24} {1,5} files {2,8:N1} MB' -f $_.Name, $_.Count, (($_.Group | Measure-Object Length -Sum).Sum / 1MB)
}
"The game's code: $module, SHA-256 $moduleHash"
"The version patch: $versionPatchName, SHA-256 $patchHash"
if ($NoZip) { return }
$zip = Join-Path $packages "$folderName-$Version.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
# (ZipFile rather than Compress-Archive, whose entries in Windows PowerShell 5.1 can have backslashes in their paths.)
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($package, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $true)
"Packaged $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB)"
