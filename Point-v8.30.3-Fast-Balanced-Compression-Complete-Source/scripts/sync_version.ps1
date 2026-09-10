[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
if ($version -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
    throw 'VERSION must use major.minor.patch numeric format.'
}

$resource = @"
// Generated from VERSION by scripts/sync_version.ps1.
#define POINT_VERSION_MAJOR $($Matches[1])
#define POINT_VERSION_MINOR $($Matches[2])
#define POINT_VERSION_PATCH $($Matches[3])
#define POINT_VERSION_BUILD 0
#define POINT_VERSION_STRING "$version"
"@
$inno = @"
; Generated from VERSION by scripts/sync_version.ps1.
#define MyAppVersion "$version"
"@

Set-Content (Join-Path $root 'src\point_version.rcinc') $resource -Encoding ascii
Set-Content (Join-Path $root 'installer\point_version.iss') $inno -Encoding ascii
Write-Host "Generated Point version metadata for $version."
