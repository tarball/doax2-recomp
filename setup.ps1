# Builds Dead or Alive Xtreme 2 from source for your own disc image and its Title Update 2: checks the tools, makes
# Title Update 2's executable from the disc's and the update's package, as the console does, recompiles it, builds the
# game, and puts it in a folder of its own with a shortcut and the version patch that plays the disc as Title Update 2.
# A release does without all this: its doax2.exe runs from the disc image as it is, with the same patch (see
# README.md). The game made here works the same way, reading the game from the disc image that settings.ini points at.
#
# Usage: powershell -ExecutionPolicy Bypass -File setup.ps1 [-Iso <disc image>] [-Tu2Package <package>]
#   [-Destination <folder>]
#   -Iso defaults to the first .iso in private\ or this folder, else asks.
#   -Tu2Package is the USA disc's Title Update 2 package, TU_1A461UI_000000C000000.00000000000G3 (Microsoft's, from an
#   Xbox 360's hard disk): by default that file in private\ or this folder, else asks.
#   -Destination defaults to game\ in this folder. Running setup again updates the game there, keeping its saves and
#   settings.
param(
    [string]$Iso = '',
    [string]$Tu2Package = '',
    [string]$Destination = ''
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
# The game: its name, executable and XenonRecomp config, and the default.xex of the disc this project supports, Dead or
# Alive Xtreme 2 (USA), title 544307D2. The config describes Title Update 2's, which the update's package for that disc
# makes from it (uncompressed and unencrypted, as tools\patchxex writes it), with its image; the version patch
# (runtime/disc_image.cpp's other version) makes the same from the disc as the game starts, but for the code and .pdata,
# which the game's code module holds.
$title = 'Dead or Alive Xtreme 2'
$exe = 'doax2.exe'
$config = 'config\DOAX2.toml'
$xexHash = 'C4A14853E1F7AF951BE34F380604113703638780B36D5E74E674FE7431992870'
$tu2PackageName = 'TU_1A461UI_000000C000000.00000000000G3'
$tu2XexHash = 'E7729FE54442466D7CDD592DEE704B3589785353EC0EECE3456003DB9FC7BFB5'
$tu2ImageHash = 'B3BEEE9902FD217389E935BC80687F87FEEA1205FB91222F1457F408DA248463'
$versionPatchName = 'doax2_tu2.vpatch'
$versionPatchPieces = @('--no-code', '--leave', '.pdata')

function Step([string]$text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Fail([string]$text) { Write-Host "`n$text" -ForegroundColor Red; exit 1 }

Step 'Checking the tools'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = $null
if (Test-Path $vswhere) { $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Llvm.Clang -property installationPath }
if (-not $vs) { Fail 'Needs Visual Studio 2026 (Build Tools or any edition) with "Desktop development with C++" and "C++ Clang tools for Windows" (see BUILD.md).' }
Write-Host "Visual Studio: $vs"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Fail 'Needs Python 3 (see BUILD.md).' }
$xenonRecomp = $env:XENONRECOMP_ROOT
if (-not $xenonRecomp) { $xenonRecomp = Join-Path (Split-Path $root -Parent) 'XenonRecomp' }
if (-not (Test-Path (Join-Path $xenonRecomp 'thirdparty\simde\x86'))) {
    Fail "Needs the XenonRecomp checkout (doa4 branch, with its submodules) at $xenonRecomp, or XENONRECOMP_ROOT set to it (see BUILD.md)."
}
Write-Host "XenonRecomp: $xenonRecomp"

Step 'Finding the disc image'
if (-not $Iso) {
    $found = @(Get-ChildItem (Join-Path $root 'private\*.iso'), (Join-Path $root '*.iso') -ErrorAction SilentlyContinue)
    if ($found.Count) { $Iso = $found[0].FullName }
}
if (-not $Iso) {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "Your $title disc image"
    $dialog.Filter = 'Disc images (*.iso)|*.iso|All files (*.*)|*.*'
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { Fail 'No disc image chosen.' }
    $Iso = $dialog.FileName
}
if (-not (Test-Path $Iso)) { Fail "There's no $Iso." }
$Iso = (Resolve-Path $Iso).Path
Write-Host $Iso

Step 'Finding the Title Update 2 package'
if (-not $Tu2Package) {
    foreach ($candidate in (Join-Path $root "private\$tu2PackageName"), (Join-Path $root $tu2PackageName)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $Tu2Package = $candidate; break }
    }
}
if (-not $Tu2Package) {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "$title's Title Update 2 for the USA disc ($tu2PackageName)"
    $dialog.Filter = "Title Update 2 ($tu2PackageName)|$tu2PackageName|All files (*.*)|*.*"
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { Fail 'No Title Update 2 package chosen.' }
    $Tu2Package = $dialog.FileName
}
if (-not (Test-Path -LiteralPath $Tu2Package -PathType Leaf)) { Fail "There's no $Tu2Package." }
$Tu2Package = (Resolve-Path -LiteralPath $Tu2Package).Path
Write-Host $Tu2Package

Step "Making Title Update 2's executable"
# As the console makes it: the package's delta (default.xexp) applied to the disc's default.xex, then its image, which
# must match the header's page hashes. In private\: the disc's executable in base\, the package's files in tu2\.
$private = Join-Path $root 'private'
$base = Join-Path $private 'base'
$update = Join-Path $private 'tu2'
New-Item -ItemType Directory -Force $base | Out-Null
if (Test-Path $update) { Remove-Item -Recurse -Force $update }
$discXex = Join-Path $base 'default.xex'
& python -I (Join-Path $root 'tools\xdvdfs.py') $Iso extract default.xex $discXex
if ($LASTEXITCODE) { Fail "Can't read default.xex from $Iso. Is it an Xbox 360 disc image?" }
$hash = (Get-FileHash $discXex -Algorithm SHA256).Hash
if ($hash -ne $xexHash) {
    Fail "This disc's default.xex (SHA-256 $hash) isn't the one this project supports: $title (USA, title 544307D2)."
}
& python -I (Join-Path $root 'tools\stfs.py') extract $Tu2Package $update
if ($LASTEXITCODE) { Fail "Can't read $Tu2Package. Is it a title update's package?" }
$patchxex = Join-Path $root 'tools\patchxex\patchxex.exe'
if (-not (Test-Path $patchxex)) {
    Write-Host 'Building tools\patchxex'
    & cmd.exe /c call (Join-Path $root 'tools\patchxex\build.cmd')
    if ($LASTEXITCODE) { Fail "Can't build tools\patchxex." }
}
$xex = Join-Path $private 'default.xex'
$image = Join-Path $private 'default.pe'
& $patchxex apply $discXex (Join-Path $update 'default.xexp') $xex | Select-Object -Last 1
if ($LASTEXITCODE) { Fail "$Tu2Package doesn't update this disc's default.xex. Is it its Title Update 2, $tu2PackageName?" }
& python -I (Join-Path $root 'tools\xexpe.py') $xex $image | Select-Object -Last 1
if ($LASTEXITCODE) { Fail "Title Update 2's image doesn't match its header." }
foreach ($file in @(@($xex, $tu2XexHash), @($image, $tu2ImageHash))) {
    if ((Get-FileHash $file[0] -Algorithm SHA256).Hash -ne $file[1]) {
        Fail "$Tu2Package and the disc don't make Title Update 2's executable ($(Split-Path -Leaf $file[0]) isn't). Is it the USA disc's package, $tu2PackageName?"
    }
}

Step 'Making the version patch'
# What plays the disc as Title Update 2, as a release's does (runtime/disc_image.h): Title Update 2's header and its
# image but the code and .pdata, made from the disc's executable.
$versionPatch = Join-Path $private $versionPatchName
$tool = Join-Path $root 'tools\versionpatch.py'
$versions = @('--source-disc', $Iso, '--target-xex', $xex, $image)
& python -I $tool build $versionPatch @versions @versionPatchPieces | Select-Object -Last 1
if ($LASTEXITCODE) { Fail 'Making the version patch failed.' }
& python -I $tool verify $versionPatch @versions | Select-Object -Last 1
if ($LASTEXITCODE) { Fail "The version patch doesn't make Title Update 2's executable from the disc's." }

Step 'Recompiling the game code'
$recompilerBuild = Join-Path $xenonRecomp 'out\build\x64-Clang-Release'
$recompiler = Join-Path $recompilerBuild 'XenonRecomp\XenonRecomp.exe'
if (-not (Test-Path $recompiler)) {
    Write-Host 'Building XenonRecomp'
    & cmd.exe /c call (Join-Path $root 'tools\env.cmd') '&&' cmake -S $xenonRecomp -B $recompilerBuild -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo `
        -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl '&&' cmake --build $recompilerBuild --target XenonRecomp
    if ($LASTEXITCODE) { Fail "Can't build XenonRecomp." }
}
Push-Location $root
try {
    & $recompiler $config (Join-Path $xenonRecomp 'XenonUtils\ppc_context.h') | Select-Object -Last 1
    $code = $LASTEXITCODE
}
finally { Pop-Location }
if ($code) { Fail 'XenonRecomp failed.' }

if (-not (Test-Path (Join-Path $root 'third_party\ffmpeg\bin'))) {
    Step 'FFmpeg'
    $answer = Read-Host 'The game decodes its music, voices and effects with FFmpeg. Download its pinned build (about 90 MB)? [Y/n]'
    if ($answer -notmatch '^[nN]') {
        & powershell -ExecutionPolicy Bypass -File (Join-Path $root 'tools\getffmpeg.ps1')
        if ($LASTEXITCODE) { Fail "Can't get FFmpeg." }
    }
    else { Write-Host 'Without FFmpeg the game is silent; run setup again to add it.' -ForegroundColor Yellow }
}

Step 'Building the game'
& cmd.exe /c call (Join-Path $root 'build.cmd') Release
if ($LASTEXITCODE) { Fail 'The build failed.' }

if (-not $Destination) { $Destination = Join-Path $root 'game' }
New-Item -ItemType Directory -Force $Destination | Out-Null
$Destination = (Resolve-Path $Destination).Path
Step "Putting the game in $Destination"
$data = Join-Path $Destination 'data'
New-Item -ItemType Directory -Force $data | Out-Null
$build = Join-Path $root 'build\Release'
Copy-Item (Join-Path $build $exe) $Destination -Force
Copy-Item (Join-Path $build '*.dll') $Destination -Force
# The version patch, beside the game's executable, where it looks for it.
Copy-Item -LiteralPath $versionPatch (Join-Path $Destination $versionPatchName) -Force
$ffmpegLicense = Join-Path $root 'third_party\ffmpeg\LICENSE.txt'
if (Test-Path $ffmpegLicense) { Copy-Item $ffmpegLicense (Join-Path $Destination 'FFmpeg LICENSE.txt') -Force }
# The game makes its executable from the disc image with the version patch, as a release does: copies an earlier setup
# put here go.
foreach ($name in 'default.xex', 'default.pe') {
    if (Test-Path (Join-Path $data $name)) { Remove-Item -Force (Join-Path $data $name) }
}
# settings.ini: the disc image, with any other settings already there.
$settings = Join-Path $data 'settings.ini'
$kept = @()
if (Test-Path $settings) {
    $kept = @(Get-Content $settings | Where-Object {
        $_ -notmatch '^\s*disc_image\s*=' -and $_ -ne '[game]' -and $_ -ne '; The disc image the game runs from.' -and
        $_ -notmatch "^; $title recomp settings" })
}
$lines = @("; $title recomp settings", '[game]', '; The disc image the game runs from.', "disc_image = $Iso") + $kept
Set-Content $settings $lines -Encoding Default
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $Destination "$title.lnk"))
$shortcut.TargetPath = Join-Path $Destination $exe
$shortcut.WorkingDirectory = $Destination
$shortcut.Save()

Step 'Done'
Write-Host "Play with `"$Destination\$title.lnk`" (or $exe there): it plays your disc as Title Update 2, with $versionPatchName."
Write-Host "Saves, settings and the log ($([IO.Path]::ChangeExtension($exe, 'log'))) are in $data."
Write-Host 'The first run copies 1.7 GB of the game to the hard disk folder in data\hdd (for about 7 minutes, in the background),'
Write-Host 'and compiles the shaders in the background for a minute or two: until then parts of a scene can appear late.'
