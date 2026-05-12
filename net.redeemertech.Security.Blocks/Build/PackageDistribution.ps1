param(
    [Parameter(Mandatory = $true)]
    [string] $RootDir,

    [Parameter(Mandatory = $true)]
    [string] $OutputDir,

    [Parameter(Mandatory = $true)]
    [string] $ConfigurationName,

    [Parameter(Mandatory = $true)]
    [string] $PlatformName
)

$ErrorActionPreference = "Stop"

function Copy-FileIfExists {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Source,

        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        return $true
    }

    return $false
}

function Copy-FirstMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Roots,

        [Parameter(Mandatory = $true)]
        [string] $Filter,

        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        $match = Get-ChildItem -LiteralPath $root -Filter $Filter -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $match) {
            Copy-Item -LiteralPath $match.FullName -Destination $Destination -Force
            return $true
        }
    }

    return $false
}

$RootDir = (Resolve-Path -LiteralPath $RootDir).Path
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$JavascriptDistDir = Join-Path $RootDir "net.redeemertech.Security.Javascript\dist"
$platformOutputSegment = if ($PlatformName -eq "AnyCPU") { "" } else { "$PlatformName\" }
$securityOutputDir = Join-Path $RootDir "net.redeemertech.Security\bin\$platformOutputSegment$ConfigurationName"
$blocksOutputDir = Join-Path $RootDir "net.redeemertech.Security.Blocks\bin\$platformOutputSegment$ConfigurationName"

if (-not (Test-Path -LiteralPath $JavascriptDistDir -PathType Container)) {
    throw "JavaScript dist directory was not found: $JavascriptDistDir"
}

$versionSourcePath = Join-Path $securityOutputDir "net.redeemertech.Security.dll"
if (-not (Test-Path -LiteralPath $versionSourcePath -PathType Leaf)) {
    throw "Could not find net.redeemertech.Security.dll to determine the package version: $versionSourcePath"
}

$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($versionSourcePath).FileVersion
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Could not determine package version from $versionSourcePath."
}

$packageName = "net.redeemertech.Security_$version"
$stagingRoot = Join-Path $RootDir "net.redeemertech.Security.Blocks\obj\Package\$packageName"
$binStagingDir = Join-Path $stagingRoot "bin"
$pluginStagingDir = Join-Path $stagingRoot "Plugins\net_redeemertech\Security"
$zipPath = Join-Path $OutputDir "$packageName.zip"

if (Test-Path -LiteralPath $stagingRoot) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $binStagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $pluginStagingDir -Force | Out-Null

$dllSourceDirs = @($blocksOutputDir, $securityOutputDir) | Select-Object -Unique
$dllNames = @(
    "net.redeemertech.Security.dll",
    "net.redeemertech.Security.Blocks.dll",
    "DuckDB.NET.Bindings.dll",
    "DuckDB.NET.Data.dll",
    "System.Buffers.dll",
    "System.Memory.dll",
    "System.Numerics.Vectors.dll",
    "System.Runtime.CompilerServices.Unsafe.dll"
)

foreach ($dllName in $dllNames) {
    foreach ($sourceDir in $dllSourceDirs) {
        if (Copy-FileIfExists -Source (Join-Path $sourceDir $dllName) -Destination $binStagingDir) {
            break
        }
    }
}

$duckDbSearchRoots = @(
    $blocksOutputDir,
    $securityOutputDir,
    (Join-Path $RootDir "Rock\packages\DuckDB.NET.Bindings.Full.1.4.4"),
    (Join-Path $RootDir "Rock\packages\DuckDB.NET.Data.Full.1.4.4"),
    (Join-Path $RootDir "..\..\RockBase")
)

if (-not (Copy-FirstMatch -Roots $duckDbSearchRoots -Filter "duckdb.dll" -Destination $binStagingDir)) {
    throw "duckdb.dll was not found in the build output or known package locations."
}

Get-ChildItem -LiteralPath $JavascriptDistDir -File -Recurse |
    Where-Object { $_.Extension -ne ".map" } |
    ForEach-Object {
        $relativePath = $_.FullName.Substring($JavascriptDistDir.Length).TrimStart([char[]]@('\', '/'))
        $destinationPath = Join-Path $pluginStagingDir $relativePath
        $destinationDir = Split-Path -Parent $destinationPath

        if (-not (Test-Path -LiteralPath $destinationDir -PathType Container)) {
            New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
        }

        Copy-Item -LiteralPath $_.FullName -Destination $destinationPath -Force
    }

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Compress-Archive -Path (Join-Path $stagingRoot "*") -DestinationPath $zipPath -Force
Write-Host "Created distribution package: $zipPath"
