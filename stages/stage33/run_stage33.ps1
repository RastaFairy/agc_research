[CmdletBinding()]
param(
    [string]$StageDir = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [string]$GlslangVersion = "16.5.0",
    [string]$IcdJson = "",
    [switch]$SkipDownload,
    [switch]$SkipVulkanProbe
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$StageDir   = (Resolve-Path -LiteralPath $StageDir).Path
$ResultsDir = Join-Path $StageDir "stage33_results"
$ZipPath    = Join-Path $StageDir "stage33_results.zip"

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

function Find-Executable {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {
        $Command = Get-Command $Name -ErrorAction SilentlyContinue
        if ($Command) {
            return $Command.Source
        }
    }

    return $null
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    Write-Info "$FilePath $($Arguments -join ' ')"

    & $FilePath @Arguments *> $OutputFile

    return $LASTEXITCODE
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
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

if (Test-Path -LiteralPath $ResultsDir) {
    Remove-Item -LiteralPath $ResultsDir -Recurse -Force
}

New-Item -ItemType Directory -Path $ResultsDir | Out-Null

$TranscriptPath = Join-Path $ResultsDir "run.log"
$TranscriptActive = $false

try {
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $TranscriptActive = $true

    Write-Step "Environment"

    $Environment = [ordered]@{
        Timestamp    = (Get-Date).ToString("o")
        ComputerName = $env:COMPUTERNAME
        UserName     = $env:USERNAME
        PowerShell   = $PSVersionTable.PSVersion.ToString()
        OS           = $PSVersionTable.OS
        StageDir     = $StageDir
        Windows      = [Environment]::OSVersion.VersionString
    }

    $Environment |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -LiteralPath (Join-Path $ResultsDir "environment.json") `
            -Encoding UTF8

    Write-Step "Locate shaders"

    $VertexCandidates = @(
        (Join-Path $StageDir "fullscreen.vert"),
        (Join-Path $StageDir "shaders\fullscreen.vert"),
        (Join-Path $StageDir "src\fullscreen.vert")
    )

    $FragmentCandidates = @(
        (Join-Path $StageDir "solid.frag"),
        (Join-Path $StageDir "shaders\solid.frag"),
        (Join-Path $StageDir "src\solid.frag")
    )

    $VertexShader = @(
        $VertexCandidates |
            Where-Object {
                Test-Path -LiteralPath $_ -PathType Leaf
            }
    ) | Select-Object -First 1

    $FragmentShader = @(
        $FragmentCandidates |
            Where-Object {
                Test-Path -LiteralPath $_ -PathType Leaf
            }
    ) | Select-Object -First 1

    if (-not $VertexShader) {
        throw "fullscreen.vert not found."
    }

    if (-not $FragmentShader) {
        throw "solid.frag not found."
    }

    Write-Info "Vertex shader:   $VertexShader"
    Write-Info "Fragment shader: $FragmentShader"

    Copy-Item `
        -LiteralPath $VertexShader `
        -Destination (Join-Path $ResultsDir "fullscreen.vert") `
        -Force

    Copy-Item `
        -LiteralPath $FragmentShader `
        -Destination (Join-Path $ResultsDir "solid.frag") `
        -Force

    Write-Step "Locate glslang"

    $Glslang = Find-Executable @(
        "glslang.exe",
        "glslang",
        "glslangValidator.exe",
        "glslangValidator"
    )

    $LocalGlslangRoot = Join-Path `
        $StageDir `
        "third_party\glslang-$GlslangVersion"

    if (-not $Glslang -and (Test-Path -LiteralPath $LocalGlslangRoot)) {

        $LocalGlslang = @(
            Get-ChildItem `
                -Path $LocalGlslangRoot `
                -Filter "glslang.exe" `
                -Recurse `
                -File `
                -ErrorAction SilentlyContinue
        ) | Select-Object -First 1

        if ($LocalGlslang) {
            $Glslang = $LocalGlslang.FullName
        }
    }

    if (-not $Glslang) {

        if ($SkipDownload) {
            throw "glslang.exe not found and -SkipDownload was specified."
        }

        $AcquireScript = Join-Path `
            $StageDir `
            "acquire_glslang.ps1"

        if (-not (Test-Path -LiteralPath $AcquireScript -PathType Leaf)) {
            throw "Missing acquire_glslang.ps1 at $AcquireScript"
        }

        Write-Warn "glslang.exe not found. Running acquire_glslang.ps1."

        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $AcquireScript `
            -Version $GlslangVersion

        if ($LASTEXITCODE -ne 0) {
            throw "acquire_glslang.ps1 failed with exit code $LASTEXITCODE."
        }

        $LocalGlslang = @(
            Get-ChildItem `
                -Path (Join-Path $StageDir "third_party") `
                -Filter "glslang.exe" `
                -Recurse `
                -File `
                -ErrorAction SilentlyContinue
        ) | Select-Object -First 1

        if (-not $LocalGlslang) {
            throw "acquire_glslang.ps1 succeeded but glslang.exe was not found."
        }

        $Glslang = $LocalGlslang.FullName
    }

    Write-Info "Using glslang: $Glslang"

    Write-Step "glslang version"

    $GlslangVersionOutput = Join-Path `
        $ResultsDir `
        "glslang_version.txt"

    $VersionExit = Invoke-Captured `
        -FilePath $Glslang `
        -Arguments @("--version") `
        -OutputFile $GlslangVersionOutput

    if ($VersionExit -ne 0) {
        throw "glslang --version failed with exit code $VersionExit."
    }

    Write-Step "Compile GLSL -> SPIR-V"

    $VertexSpv = Join-Path `
        $ResultsDir `
        "fullscreen.vert.spv"

    $FragmentSpv = Join-Path `
        $ResultsDir `
        "solid.frag.spv"

    $VertexCompileLog = Join-Path `
        $ResultsDir `
        "fullscreen.vert.compile.txt"

    $FragmentCompileLog = Join-Path `
        $ResultsDir `
        "solid.frag.compile.txt"

    $VertexCompileExit = Invoke-Captured `
        -FilePath $Glslang `
        -Arguments @(
            "-V",
            $VertexShader,
            "-o",
            $VertexSpv
        ) `
        -OutputFile $VertexCompileLog

    $FragmentCompileExit = Invoke-Captured `
        -FilePath $Glslang `
        -Arguments @(
            "-V",
            $FragmentShader,
            "-o",
            $FragmentSpv
        ) `
        -OutputFile $FragmentCompileLog

    $CompileStatus = [ordered]@{
        Vertex = [ordered]@{
            ExitCode = $VertexCompileExit
            Output   = $VertexSpv
            Present  = Test-Path -LiteralPath $VertexSpv -PathType Leaf
        }

        Fragment = [ordered]@{
            ExitCode = $FragmentCompileExit
            Output   = $FragmentSpv
            Present  = Test-Path -LiteralPath $FragmentSpv -PathType Leaf
        }
    }

    $CompileStatus |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -LiteralPath (Join-Path $ResultsDir "compile_status.json") `
            -Encoding UTF8

    if ($VertexCompileExit -ne 0) {
        Write-Warn "Vertex shader compilation failed."
    }

    if ($FragmentCompileExit -ne 0) {
        Write-Warn "Fragment shader compilation failed."
    }

    Write-Step "Locate spirv-val"

    $SpirvVal = Find-Executable @(
        "spirv-val.exe",
        "spirv-val"
    )

    if ($SpirvVal) {
        Write-Info "spirv-val: $SpirvVal"
    }
    else {
        Write-Warn "spirv-val not available."
    }

    Write-Step "Validate SPIR-V"

    $Validation = @()

    foreach ($Spv in @(
        $VertexSpv,
        $FragmentSpv
    )) {

        if (-not (Test-Path -LiteralPath $Spv -PathType Leaf)) {
            continue
        }

        $Name = Split-Path -Leaf $Spv

        if ($SpirvVal) {

            $ValidationLog = Join-Path `
                $ResultsDir `
                "$Name.validation.txt"

            $ValidationExit = Invoke-Captured `
                -FilePath $SpirvVal `
                -Arguments @($Spv) `
                -OutputFile $ValidationLog

            $Validation += [ordered]@{
                File     = $Name
                Tool     = $SpirvVal
                ExitCode = $ValidationExit
                Status   = if ($ValidationExit -eq 0) {
                    "PASS"
                }
                else {
                    "FAIL"
                }
            }
        }
        else {

            $Validation += [ordered]@{
                File     = $Name
                Tool     = $null
                ExitCode = $null
                Status   = "UNAVAILABLE"
            }
        }
    }

    $Validation |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -LiteralPath (Join-Path $ResultsDir "spirv_validation.json") `
            -Encoding UTF8

    Write-Step "Vulkan ICD discovery"

    $IcdPaths = @()

    if ($IcdJson) {

        if (Test-Path -LiteralPath $IcdJson -PathType Leaf) {

            $ResolvedIcd = (
                Resolve-Path -LiteralPath $IcdJson
            ).Path

            $IcdPaths += $ResolvedIcd
        }
        else {
            Write-Warn "Specified ICD JSON not found: $IcdJson"
        }
    }

    $KnownVulkanRoots = @(
        "$env:ProgramFiles\VulkanSDK",
        "$env:ProgramFiles\Vulkan\Bin",
        "$env:ProgramFiles(x86)\VulkanSDK"
    )

    foreach ($Root in $KnownVulkanRoots) {

        if (-not (Test-Path -LiteralPath $Root)) {
            continue
        }

        $FoundIcds = @(
            Get-ChildItem `
                -Path $Root `
                -Recurse `
                -Include "*icd*.json" `
                -File `
                -ErrorAction SilentlyContinue
        )

        if (@($FoundIcds).Count -gt 0) {
            $IcdPaths += @(
                $FoundIcds.FullName
            )
        }
    }

    $UniqueIcdPaths = @(
        $IcdPaths |
            Where-Object {
                $_ -and
                $_.ToString().Trim().Length -gt 0
            } |
            Sort-Object -Unique
    )

    $UniqueIcdPaths |
        Set-Content `
            -LiteralPath (Join-Path $ResultsDir "vulkan_icds.txt") `
            -Encoding UTF8

    Write-Info "ICDs found: $(@($UniqueIcdPaths).Count)"

    Write-Step "vulkaninfo"

    $VulkanInfo = Find-Executable @(
        "vulkaninfo.exe",
        "vulkaninfo"
    )

    $VulkanInfoOutput = Join-Path `
        $ResultsDir `
        "vulkaninfo.txt"

    $VulkanInfoExit = $null

    if ($VulkanInfo -and -not $SkipVulkanProbe) {

        try {

            & $VulkanInfo --summary *> $VulkanInfoOutput

            $VulkanInfoExit = $LASTEXITCODE
        }
        catch {

            $_ |
                Out-File `
                    -LiteralPath $VulkanInfoOutput `
                    -Encoding UTF8

            $VulkanInfoExit = -1
        }
    }
    else {

        "vulkaninfo unavailable" |
            Set-Content `
                -LiteralPath $VulkanInfoOutput `
                -Encoding UTF8
    }

    Write-Step "Hashes"

    $HashRecords = @()

    $FilesToHash = @(
        (Join-Path $ResultsDir "fullscreen.vert"),
        (Join-Path $ResultsDir "solid.frag"),
        $VertexSpv,
        $FragmentSpv
    )

    foreach ($Path in $FilesToHash) {

        if (Test-Path -LiteralPath $Path -PathType Leaf) {

            $Item = Get-Item -LiteralPath $Path

            $HashRecords += [ordered]@{
                File   = $Item.Name
                Size   = $Item.Length
                SHA256 = Get-Sha256 -Path $Path
            }
        }
    }

    $HashRecords |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -LiteralPath (Join-Path $ResultsDir "hashes.json") `
            -Encoding UTF8

    Write-Step "Summary"

    $Summary = [ordered]@{
        Stage = 33

        Timestamp = (Get-Date).ToString("o")

        Glslang = [ordered]@{
            Path             = $Glslang
            RequestedVersion = $GlslangVersion
            BinarySHA256     = Get-Sha256 -Path $Glslang
        }

        Compile = $CompileStatus

        SPIRVValidation = $Validation

        Vulkan = [ordered]@{
            VulkanInfoTool = $VulkanInfo
            VulkanInfoExit = $VulkanInfoExit
            ICDCount       = @($UniqueIcdPaths).Count
            ICDs           = @($UniqueIcdPaths)
        }

        SPIRVArtifacts = [ordered]@{
            Vertex =
                if (Test-Path -LiteralPath $VertexSpv -PathType Leaf) {
                    [ordered]@{
                        Present = $true
                        Size    = (Get-Item $VertexSpv).Length
                        SHA256  = Get-Sha256 -Path $VertexSpv
                    }
                }
                else {
                    [ordered]@{
                        Present = $false
                    }
                }

            Fragment =
                if (Test-Path -LiteralPath $FragmentSpv -PathType Leaf) {
                    [ordered]@{
                        Present = $true
                        Size    = (Get-Item $FragmentSpv).Length
                        SHA256  = Get-Sha256 -Path $FragmentSpv
                    }
                }
                else {
                    [ordered]@{
                        Present = $false
                    }
                }
        }
    }

    $Summary |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath (Join-Path $ResultsDir "SUMMARY.json") `
            -Encoding UTF8

    #
    # IMPORTANT:
    # Stop the transcript BEFORE Compress-Archive touches run.log.
    #
    if ($TranscriptActive) {
        Stop-Transcript | Out-Null
        $TranscriptActive = $false
    }

    Write-Step "Create result ZIP"

    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force
    }

    Compress-Archive `
        -Path (Join-Path $ResultsDir "*") `
        -DestinationPath $ZipPath `
        -CompressionLevel Optimal

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Stage 33 result package created:" -ForegroundColor Green
    Write-Host $ZipPath -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
}
catch {

    if ($TranscriptActive) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # Ignore transcript cleanup errors while handling the real error.
        }

        $TranscriptActive = $false
    }

    $ErrorMessage = $_.Exception.Message

    Write-Host ""
    Write-Host "FATAL ERROR" -ForegroundColor Red
    Write-Host $ErrorMessage -ForegroundColor Red

    try {
        $_ |
            Out-File `
                -LiteralPath (Join-Path $ResultsDir "fatal_error.txt") `
                -Encoding UTF8
    }
    catch {
        # Avoid masking the original error.
    }

    throw
}
finally {

    if ($TranscriptActive) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # Safe cleanup.
        }
    }
}