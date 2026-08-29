[CmdletBinding()]
param(
    [string]$SdkDir = 'D:\sdk-master',
    [string]$WorkDir = 'D:\agc_work\sce_stubs'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SdkDir = (Resolve-Path -LiteralPath $SdkDir).Path
$WorkDir = (Resolve-Path -LiteralPath $WorkDir).Path
$Results = Join-Path $WorkDir 'stage38_results'

if (Test-Path $Results) { Remove-Item -Recurse -Force $Results }
New-Item -ItemType Directory -Force $Results | Out-Null

function Invoke-Tool {
    param([string]$CmdFile, [string[]]$Args, [string]$Log)
    Write-Host "[INFO] $CmdFile $($Args -join ' ')"
    if ($CmdFile.ToLowerInvariant().EndsWith('.cmd')) {
        & cmd.exe /d /c $CmdFile @Args *> $Log
    } else {
        & $CmdFile @Args *> $Log
    }
    return $LASTEXITCODE
}

$Compiler = Join-Path $SdkDir 'host\win\prospero-clang.cmd'
if (-not (Test-Path -LiteralPath $Compiler -PathType Leaf)) {
    throw "prospero-clang.cmd not found: $Compiler"
}

$Sources = @(
    'libSceAgc.c',
    'libSceAgcDriver.c',
    'libSceAgcVsh.c'
) | ForEach-Object { Join-Path $WorkDir $_ }

foreach ($Source in $Sources) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Generated stub missing: $Source"
    }
}

$Manifest = [ordered]@{
    sdk = $SdkDir
    compiler = $Compiler
    sources = @()
    results = $Results
}

foreach ($Source in $Sources) {
    $Name = [IO.Path]::GetFileNameWithoutExtension($Source)
    $Obj = Join-Path $Results "$Name.o"
    $Log = Join-Path $Results "$Name.compile.txt"

    # Mirror the flags from sdk-master/sce_stubs/Makefile.
    $Args = @(
        '-c',
        '-ffreestanding',
        '-fno-builtin',
        '-nostdlib',
        '-fPIC',
        '-target', 'x86_64-sie-ps5',
        '-fno-plt',
        '-fno-stack-protector',
        '-Wall',
        '-Werror',
        '-fvisibility-nodllstorageclass=default',
        '-I', (Join-Path $SdkDir 'include'),
        '-o', $Obj,
        $Source
    )

    Write-Host ""
    Write-Host "==> Compile $Name" -ForegroundColor Cyan
    $Exit = Invoke-Tool -CmdFile $Compiler -Args $Args -Log $Log

    $Record = [ordered]@{
        source = $Source
        object = $Obj
        log = $Log
        exit_code = $Exit
        object_present = (Test-Path -LiteralPath $Obj -PathType Leaf)
    }

    $Manifest.sources += $Record

    if ($Exit -ne 0) {
        Write-Host "[FAIL] $Name exit=$Exit" -ForegroundColor Red
        throw "$Name compilation failed. See $Log"
    }

    Write-Host "[PASS] $Name -> $Obj" -ForegroundColor Green
}

$Manifest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $Results 'STAGE38_MANIFEST.json') -Encoding UTF8

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "Stage 38 compile: PASS" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "Results: $Results"
