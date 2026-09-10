[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
if ($version -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
    throw 'VERSION must use major.minor.patch numeric format.'
}

$rcVersion = Get-Content (Join-Path $root 'src\point_version.rcinc') -Raw
$issVersion = Get-Content (Join-Path $root 'installer\point_version.iss') -Raw
$resource = Get-Content (Join-Path $root 'src\point.rc') -Raw
$installer = Get-Content (Join-Path $root 'installer\Point.iss') -Raw
$readmeFirst = Get-Content (Join-Path $root 'README.md') -TotalCount 1

$expectedParts = @(
    "#define POINT_VERSION_MAJOR $($Matches[1])",
    "#define POINT_VERSION_MINOR $($Matches[2])",
    "#define POINT_VERSION_PATCH $($Matches[3])",
    '#define POINT_VERSION_BUILD 0',
    "#define POINT_VERSION_STRING `"$version`""
)
foreach ($part in $expectedParts) {
    if (-not $rcVersion.Contains($part)) {
        throw "Resource version metadata does not match VERSION: $part"
    }
}
if (-not $issVersion.Contains("#define MyAppVersion `"$version`"")) {
    throw 'Inno Setup version metadata does not match VERSION.'
}
if (-not $resource.Contains('#include "point_version.rcinc"')) {
    throw 'point.rc must consume generated point_version.rcinc.'
}
if (-not $installer.Contains('#include "point_version.iss"') -or
    -not $installer.Contains('OutputBaseFilename=Point-v{#MyAppVersion}-Setup')) {
    throw 'Point.iss must consume the generated version and derive its filename.'
}
if ($readmeFirst -ne "# Point v$version — Fast and Balanced Compression") {
    throw "README release header does not match VERSION ($version)."
}

$stalePaths = @(
    '{app}\Inbox', '{app}\Workspace', '{app}\Exports', '{app}\Logs',
    '{app}\Fetcher\Staging', '{app}\BrowserFetcher\Staging'
)
$textFiles = Get-ChildItem $root -Recurse -File | Where-Object {
    $_.Extension -in @('.iss', '.md', '.ps1', '.bat', '.cpp', '.h', '.yml', '.yaml') -and
    $_.FullName -notmatch '[\\/]build[^\\/]*[\\/]' -and
    $_.FullName -ne $PSCommandPath
}
foreach ($file in $textFiles) {
    $content = Get-Content $file.FullName -Raw
    foreach ($stale in $stalePaths) {
        if ($content.Contains($stale)) {
            throw "Stale installed-data path '$stale' found in $($file.FullName)."
        }
    }
}

Write-Host "Release metadata and data paths verified for Point v$version."
