[CmdletBinding()]
param(
    [string]$StageDir = (Split-Path -Parent $MyInvocation.MyCommand.Path),

    [string]$SdkPath = "",

    [switch]$Compile,

    [switch]$Strict
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$StageDir = (Resolve-Path -LiteralPath $StageDir).Path
$ResultsDir = Join-Path $StageDir "results"

if (Test-Path -LiteralPath $ResultsDir) {
    Remove-Item -LiteralPath $ResultsDir -Recurse -Force
}

New-Item -ItemType Directory -Path $ResultsDir | Out-Null

$ReportPath = Join-Path $ResultsDir "STAGE36_REPORT.json"
$TextPath   = Join-Path $ResultsDir "STAGE36_REPORT.txt"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Find-CommandPath {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {
        $Cmd = Get-Command $Name -ErrorAction SilentlyContinue
        if ($Cmd) {
            return $Cmd.Source
        }
    }

    return $null
}

function Get-ExistingCandidates {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Paths
    )

    $Result = @()

    foreach ($Path in $Paths) {
        if (Test-Path -LiteralPath $Path) {
            $Result += (Resolve-Path -LiteralPath $Path).Path
        }
    }

    return @($Result)
}

function Find-FileRecursive {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Root,

        [Parameter(Mandatory=$true)]
        [string[]]$Names
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return @()
    }

    $Found = @()

    foreach ($Name in $Names) {
        $Found += @(
            Get-ChildItem `
                -LiteralPath $Root `
                -Filter $Name `
                -Recurse `
                -File `
                -ErrorAction SilentlyContinue
        )
    }

    return @(
        $Found |
            Sort-Object FullName -Unique
    )
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (
        Get-FileHash `
            -LiteralPath $Path `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

$Report = [ordered]@{
    stage = 36
    timestamp = (Get-Date).ToString("o")

    environment = [ordered]@{
        windows_version = [Environment]::OSVersion.VersionString
        powershell      = $PSVersionTable.PSVersion.ToString()
        computer_name   = $env:COMPUTERNAME
        user_name       = $env:USERNAME
    }

    sdk = [ordered]@{
        requested_path = $SdkPath
        detected_path  = $null
        status         = "UNKNOWN"
    }

    toolchain = [ordered]@{
        clang = $null
        clangxx = $null
        make = $null
        cmake = $null
        ninja = $null
    }

    agc_driver = [ordered]@{
        library_candidates = @()
        stub_candidates    = @()
        symbol_hits        = @()
        status             = "UNKNOWN"
    }

    compile = [ordered]@{
        requested = [bool]$Compile
        status = "NOT_REQUESTED"
        exit_code = $null
    }

    result = "UNKNOWN"
}

try {
    Write-Step "Environment"

    Write-Info "Windows: $($Report.environment.windows_version)"
    Write-Info "PowerShell: $($Report.environment.powershell)"

    Write-Step "Detect PS5 Payload SDK"

    $SdkCandidates = @()

    if ($SdkPath) {
        $SdkCandidates += $SdkPath
    }

    if ($env:PS5_PAYLOAD_SDK) {
        $SdkCandidates += $env:PS5_PAYLOAD_SDK
    }

    $SdkCandidates += @(
        "C:\ps5-payload-sdk",
        "C:\ps5-payload-dev\sdk",
        "C:\src\ps5-payload-dev\sdk",
        "D:\ps5-payload-sdk",
        "D:\ps5-payload-dev\sdk",
        "$HOME\ps5-payload-sdk",
        "$HOME\src\ps5-payload-dev\sdk"
    )

    $SdkCandidates = @(
        $SdkCandidates |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    $SdkDetected = $null

    foreach ($Candidate in $SdkCandidates) {

        if (-not (Test-Path -LiteralPath $Candidate -PathType Container)) {
            continue
        }

        $Resolved = (Resolve-Path -LiteralPath $Candidate).Path

        $IsSdk = (
            (Test-Path (Join-Path $Resolved "Makefile.inc")) -or
            (Test-Path (Join-Path $Resolved "prospero")) -or
            (Test-Path (Join-Path $Resolved "include")) -and
            (Test-Path (Join-Path $Resolved "crt"))
        )

        if ($IsSdk) {
            $SdkDetected = $Resolved
            break
        }
    }

    if ($SdkDetected) {

        $Report.sdk.detected_path = $SdkDetected
        $Report.sdk.status = "FOUND"

        Write-Info "SDK: $SdkDetected"
    }
    else {

        $Report.sdk.status = "NOT_FOUND"

        Write-Warn "PS5 Payload SDK not found."

        if ($Strict) {
            throw "PS5 Payload SDK not found."
        }
    }

    Write-Step "Detect toolchain"

    $Clang = Find-CommandPath @(
        "clang.exe",
        "clang"
    )

    $ClangXX = Find-CommandPath @(
        "clang++.exe",
        "clang++"
    )

    $Make = Find-CommandPath @(
        "make.exe",
        "make"
    )

    $CMake = Find-CommandPath @(
        "cmake.exe",
        "cmake"
    )

    $Ninja = Find-CommandPath @(
        "ninja.exe",
        "ninja"
    )

    $Report.toolchain.clang = $Clang
    $Report.toolchain.clangxx = $ClangXX
    $Report.toolchain.make = $Make
    $Report.toolchain.cmake = $CMake
    $Report.toolchain.ninja = $Ninja

    Write-Info "clang  = $Clang"
    Write-Info "clang++ = $ClangXX"
    Write-Info "make   = $Make"
    Write-Info "cmake  = $CMake"
    Write-Info "ninja  = $Ninja"

    Write-Step "Locate libSceAgcDriver artefacts"

    $SearchRoots = @()

    if ($SdkDetected) {
        $SearchRoots += $SdkDetected
    }

    # The Stage 36 package itself may contain extracted/source material.
    $SearchRoots += $StageDir

    $SearchRoots = @(
        $SearchRoots |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
            Sort-Object -Unique
    )

    $LibraryNames = @(
        "libSceAgcDriver.a",
        "libSceAgcDriver_stub.a",
        "libSceAgcDriver_stub.lib",
        "libSceAgcDriver.lib",
        "libSceAgcDriver.c",
        "libSceAgcDriver.h",
        "libSceAgcDriver.sprx"
    )

    $LibraryHits = @()

    foreach ($Root in $SearchRoots) {
        $LibraryHits += @(
            Find-FileRecursive `
                -Root $Root `
                -Names $LibraryNames
        )
    }

    $LibraryHits = @(
        $LibraryHits |
            Sort-Object FullName -Unique
    )

    $Report.agc_driver.library_candidates = @(
        $LibraryHits |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName
                    size = $_.Length
                    sha256 = Get-Sha256 -Path $_.FullName
                }
            }
    )

    if ($LibraryHits.Count -gt 0) {
        Write-Info "Found $($LibraryHits.Count) AGC Driver artefact(s)."

        foreach ($Hit in $LibraryHits) {
            Write-Info "  $($Hit.FullName)"
        }
    }
    else {
        Write-Warn "No libSceAgcDriver artefact found in searched roots."
    }

    Write-Step "Locate generated SCE stubs"

    $StubRoots = @()

    if ($SdkDetected) {
        $StubRoots += @(
            (Join-Path $SdkDetected "sce_stubs"),
            (Join-Path $SdkDetected "lib"),
            (Join-Path $SdkDetected "build"),
            (Join-Path $SdkDetected "samples")
        )
    }

    $StubRoots += $StageDir

    $StubRoots = @(
        $StubRoots |
            Where-Object {
                $_ -and
                (Test-Path -LiteralPath $_ -PathType Container)
            } |
            Sort-Object -Unique
    )

    $StubNames = @(
        "libSceAgcDriver.c",
        "libSceAgcDriver.h",
        "libSceAgcDriver.a",
        "libSceAgcDriver_stub.a",
        "libSceAgcDriver.lib",
        "libSceAgcDriver_stub.lib"
    )

    $StubHits = @()

    foreach ($Root in $StubRoots) {
        $StubHits += @(
            Find-FileRecursive `
                -Root $Root `
                -Names $StubNames
        )
    }

    $StubHits = @(
        $StubHits |
            Sort-Object FullName -Unique
    )

    $Report.agc_driver.stub_candidates = @(
        $StubHits |
            ForEach-Object {
                [ordered]@{
                    path = $_.FullName
                    size = $_.Length
                    sha256 = Get-Sha256 -Path $_.FullName
                }
            }
    )

    if ($StubHits.Count -gt 0) {
        Write-Info "Found $($StubHits.Count) candidate stub artefact(s)."
    }
    else {
        Write-Warn "No generated libSceAgcDriver stub found."
    }

    Write-Step "Search for sceAgcDriverSubmitDcb"

    $SourceFiles = @()

    foreach ($Hit in $StubHits) {

        $Ext = [IO.Path]::GetExtension($Hit.FullName).ToLowerInvariant()

        if ($Ext -in @(
            ".c",
            ".h",
            ".txt",
            ".md"
        )) {
            $SourceFiles += $Hit.FullName
        }
    }

    foreach ($Hit in $LibraryHits) {

        $Ext = [IO.Path]::GetExtension($Hit.FullName).ToLowerInvariant()

        if ($Ext -in @(
            ".c",
            ".h",
            ".txt",
            ".md"
        )) {
            $SourceFiles += $Hit.FullName
        }
    }

    # Also inspect project files in the stage directory.
    $SourceFiles += @(
        Get-ChildItem `
            -Path $StageDir `
            -Recurse `
            -Include "*.c","*.h","*.txt","*.md" `
            -File `
            -ErrorAction SilentlyContinue |
            ForEach-Object FullName
    )

    $SourceFiles = @(
        $SourceFiles |
            Sort-Object -Unique
    )

    $SymbolHits = @()

    foreach ($Source in $SourceFiles) {

        try {

            $Matches = Select-String `
                -LiteralPath $Source `
                -Pattern "sceAgcDriverSubmitDcb" `
                -SimpleMatch `
                -ErrorAction Stop

            foreach ($Match in $Matches) {

                $SymbolHits += [ordered]@{
                    file = $Source
                    line = $Match.LineNumber
                    text = $Match.Line.Trim()
                }
            }
        }
        catch {
            # Ignore unreadable/binary files.
        }
    }

    $Report.agc_driver.symbol_hits = @($SymbolHits)

    if ($SymbolHits.Count -gt 0) {

        $Report.agc_driver.status = "SYMBOL_FOUND"

        foreach ($Hit in $SymbolHits) {
            Write-Info "$($Hit.file):$($Hit.line)"
            Write-Info "  $($Hit.text)"
        }
    }
    else {

        $Report.agc_driver.status =
            if ($StubHits.Count -gt 0) {
                "STUB_FOUND_SYMBOL_NOT_FOUND"
            }
            else {
                "NOT_FOUND"
            }

        Write-Warn "sceAgcDriverSubmitDcb not found in local text sources."
    }

    Write-Step "Build ABI_CHECK.c"

    $AbiCheck = Join-Path $StageDir "ABI_CHECK.c"
    $BoundaryC = Join-Path $StageDir "agc_ps5_submit_boundary.c"
    $BoundaryH = Join-Path $StageDir "agc_ps5_submit_boundary.h"

    if (-not (Test-Path -LiteralPath $AbiCheck -PathType Leaf)) {
        Write-Warn "ABI_CHECK.c not found."
    }

    if (-not (Test-Path -LiteralPath $BoundaryC -PathType Leaf)) {
        Write-Warn "agc_ps5_submit_boundary.c not found."
    }

    if (-not (Test-Path -LiteralPath $BoundaryH -PathType Leaf)) {
        Write-Warn "agc_ps5_submit_boundary.h not found."
    }

    if ($Compile) {

        if (-not $AbiCheck) {
            throw "ABI_CHECK.c missing."
        }

        if (-not $Clang) {
            throw "clang not found; cannot compile."
        }

        Write-Info "Compile requested."

        $OutputExe = Join-Path $ResultsDir "abi_check.exe"

        $CompileArgs = @(
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            $AbiCheck,
            "-o",
            $OutputExe
        )

        $CompileLog = Join-Path `
            $ResultsDir `
            "compile.log"

        & $Clang @CompileArgs *> $CompileLog

        $CompileExit = $LASTEXITCODE

        $Report.compile.exit_code = $CompileExit

        if ($CompileExit -eq 0) {

            $Report.compile.status = "PASS"
            Write-Info "Compile PASS."

        }
        else {

            $Report.compile.status = "FAIL"
            Write-Warn "Compile FAIL. See compile.log."

            if ($Strict) {
                throw "ABI_CHECK.c compilation failed."
            }
        }
    }
    else {

        Write-Info "Compilation not requested. Use -Compile."
    }

    Write-Step "Determine result"

    if ($Report.sdk.status -eq "NOT_FOUND") {

        $Report.result = "SDK_UNAVAILABLE"

    }
    elseif (
        $Report.agc_driver.status -eq "SYMBOL_FOUND"
    ) {

        $Report.result = "SYMBOL_FOUND"

    }
    elseif (
        $Report.agc_driver.stub_candidates.Count -gt 0
    ) {

        $Report.result = "STUB_FOUND"

    }
    elseif (
        $Report.sdk.status -eq "FOUND"
    ) {

        $Report.result = "SDK_FOUND_STUB_UNAVAILABLE"

    }
    else {

        $Report.result = "UNRESOLVED"
    }

    Write-Info "RESULT = $($Report.result)"

    $Report |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath $ReportPath `
            -Encoding UTF8

    @(
        "AGC PS5 Stage 36"
        "================="
        ""
        "RESULT : $($Report.result)"
        "SDK    : $($Report.sdk.status)"
        "SDK    : $($Report.sdk.detected_path)"
        "AGCDRV : $($Report.agc_driver.status)"
        ""
        "libSceAgcDriver candidates : $($Report.agc_driver.library_candidates.Count)"
        "Generated stub candidates  : $($Report.agc_driver.stub_candidates.Count)"
        "SubmitDcb symbol hits      : $($Report.agc_driver.symbol_hits.Count)"
        ""
        "Compile requested : $($Report.compile.requested)"
        "Compile status    : $($Report.compile.status)"
        "Compile exit      : $($Report.compile.exit_code)"
        ""
        "Report:"
        "$ReportPath"
    ) | Set-Content -LiteralPath $TextPath -Encoding UTF8

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Stage 36 finished" -ForegroundColor Green
    Write-Host "RESULT = $($Report.result)" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
}
catch {

    $Message = $_.Exception.Message

    Write-Host ""
    Write-Host "FATAL ERROR" -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red

    [ordered]@{
        stage = 36
        result = "ERROR"
        error = $Message
        timestamp = (Get-Date).ToString("o")
    } |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $ReportPath -Encoding UTF8

    throw
}