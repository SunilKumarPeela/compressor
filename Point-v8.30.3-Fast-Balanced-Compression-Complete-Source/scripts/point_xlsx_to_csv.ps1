param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$CacheKey,
    [Parameter(Mandatory=$true)][string]$SafeStem
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Safe-Name([string]$Value) {
    $result = [regex]::Replace($Value, '[\x00-\x1f<>:"/\\|?*]', '_').TrimEnd(' ', '.')
    if ([string]::IsNullOrWhiteSpace($result)) { $result = 'Sheet' }
    if ($result.Length -gt 80) { $result = $result.Substring(0, 80) }
    return $result
}

function Column-Number([string]$Reference) {
    $letters = [regex]::Match($Reference, '^[A-Za-z]+').Value.ToUpperInvariant()
    $number = 0
    foreach ($character in $letters.ToCharArray()) {
        $number = ($number * 26) + ([int]$character - [int][char]'A' + 1)
    }
    return $number
}

function Csv-Value([string]$Value) {
    if ($null -eq $Value) { return '' }
    if ($Value -match '[,"\r\n]') {
        return '"' + $Value.Replace('"', '""') + '"'
    }
    return $Value
}

function Cell-Value($Cell, $SharedStrings) {
    $type = [string]$Cell.t
    $valueNode = $Cell.SelectSingleNode('./*[local-name()="v"]')
    $value = if ($null -ne $valueNode) { [string]$valueNode.InnerText } else { '' }
    if ($type -eq 's' -and $value -match '^\d+$' -and
        [int]$value -lt $SharedStrings.Count) {
        return $SharedStrings[[int]$value]
    }
    if ($type -eq 'inlineStr') {
        return (@($Cell.SelectNodes('.//*[local-name()="t"]') |
            ForEach-Object { $_.InnerText }) -join '')
    }
    if ($type -eq 'b') {
        return $(if ($value -eq '1') { 'TRUE' } else { 'FALSE' })
    }
    return $value
}

$fullInput = [IO.Path]::GetFullPath($InputPath)
$fullOutput = [IO.Path]::GetFullPath($OutputDirectory)
if (-not [IO.File]::Exists($fullInput)) { throw 'Workbook does not exist.' }
$extension = [IO.Path]::GetExtension($fullInput).ToLowerInvariant()
if ($extension -ne '.xlsx') {
    throw 'Native reader accepts only macro-free .xlsx files.'
}
[IO.Directory]::CreateDirectory($fullOutput) | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('Point-Xlsx-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporary) | Out-Null

try {
    [IO.Compression.ZipFile]::ExtractToDirectory($fullInput, $temporary)
    $workbookPath = Join-Path $temporary 'xl\workbook.xml'
    $relationsPath = Join-Path $temporary 'xl\_rels\workbook.xml.rels'
    if (-not (Test-Path -LiteralPath $workbookPath) -or -not (Test-Path -LiteralPath $relationsPath)) {
        throw 'The Office package has no workbook metadata.'
    }

    [xml]$workbook = Get-Content -LiteralPath $workbookPath -Raw
    [xml]$relations = Get-Content -LiteralPath $relationsPath -Raw
    $relationshipMap = @{}
    foreach ($relation in $relations.SelectNodes('//*[local-name()="Relationship"]')) {
        $relationshipMap[[string]$relation.Id] = [string]$relation.Target
    }

    $shared = New-Object 'System.Collections.Generic.List[string]'
    $sharedPath = Join-Path $temporary 'xl\sharedStrings.xml'
    if (Test-Path -LiteralPath $sharedPath) {
        [xml]$sharedXml = Get-Content -LiteralPath $sharedPath -Raw
        foreach ($item in $sharedXml.sst.si) {
            $pieces = @($item.SelectNodes('.//*[local-name()="t"]') | ForEach-Object { $_.InnerText })
            $shared.Add(($pieces -join ''))
        }
    }

    $generated = 0
    foreach ($sheet in $workbook.SelectNodes('//*[local-name()="sheets"]/*[local-name()="sheet"]')) {
        $relationId = [string]$sheet.GetAttribute('id', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships')
        if (-not $relationshipMap.ContainsKey($relationId)) { continue }
        $target = $relationshipMap[$relationId].Replace('/', '\')
        if ($target.StartsWith('\')) { $target = $target.TrimStart('\') }
        if ($target.StartsWith('..\')) { $sheetPath = Join-Path $temporary $target.Substring(3) }
        else { $sheetPath = Join-Path (Join-Path $temporary 'xl') $target }
        $sheetPath = [IO.Path]::GetFullPath($sheetPath)
        if (-not $sheetPath.StartsWith([IO.Path]::GetFullPath($temporary), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Unsafe worksheet path in workbook.'
        }
        if (-not (Test-Path -LiteralPath $sheetPath)) { continue }

        [xml]$sheetXml = Get-Content -LiteralPath $sheetPath -Raw
        $rows = @($sheetXml.SelectNodes('//*[local-name()="sheetData"]/*[local-name()="row"]'))
        $maximumColumn = 0
        foreach ($row in $rows) {
            foreach ($cell in @($row.SelectNodes('./*[local-name()="c"]'))) {
                $maximumColumn = [Math]::Max($maximumColumn, (Column-Number ([string]$cell.r)))
            }
        }
        if ($maximumColumn -gt 16384 -or $rows.Count -gt 2000001) { throw 'Worksheet exceeds Point safety limits.' }

        # Generated reports often place logos, descriptions, timestamps, and
        # formatting rows above the table. Detect the real header separately
        # for every worksheet. The header and data normally share the greatest
        # populated width, so the earliest maximum in a bounded preview wins.
        $headerRowIndex = 0
        $bestPopulated = 0
        $previewCount = [Math]::Min(64, $rows.Count)
        for ($rowIndex = 0; $rowIndex -lt $previewCount; $rowIndex++) {
            $populated = 0
            foreach ($cell in @($rows[$rowIndex].SelectNodes('./*[local-name()="c"]'))) {
                if (-not [string]::IsNullOrWhiteSpace((Cell-Value $cell $shared))) {
                    $populated++
                }
            }
            if ($populated -gt $bestPopulated) {
                $bestPopulated = $populated
                $headerRowIndex = $rowIndex
            }
        }
        if ($bestPopulated -lt 2) { $headerRowIndex = 0 }

        # Ignore styled/formatting-only columns beyond the actual table while
        # preserving any intentionally blank heading inside the table.
        $outputColumnCount = 0
        if ($rows.Count -gt 0) {
            foreach ($cell in @($rows[$headerRowIndex].SelectNodes('./*[local-name()="c"]'))) {
                if (-not [string]::IsNullOrWhiteSpace((Cell-Value $cell $shared))) {
                    $outputColumnCount = [Math]::Max(
                        $outputColumnCount,
                        (Column-Number ([string]$cell.r)))
                }
            }
        }
        if ($outputColumnCount -eq 0) { $outputColumnCount = $maximumColumn }

        $sheetName = Safe-Name ([string]$sheet.name)
        $outputPath = Join-Path $fullOutput ("{0}__{1}__{2}.csv" -f $CacheKey, $SafeStem, $sheetName)
        $encoding = New-Object Text.UTF8Encoding($true)
        $writer = New-Object IO.StreamWriter($outputPath, $false, $encoding)
        try {
            for ($rowIndex = $headerRowIndex; $rowIndex -lt $rows.Count; $rowIndex++) {
                $row = $rows[$rowIndex]
                $values = New-Object 'string[]' $outputColumnCount
                foreach ($cell in @($row.SelectNodes('./*[local-name()="c"]'))) {
                    $column = (Column-Number ([string]$cell.r)) - 1
                    if ($column -lt 0 -or $column -ge $outputColumnCount) { continue }
                    $values[$column] = Cell-Value $cell $shared
                }
                $writer.WriteLine((@($values | ForEach-Object { Csv-Value $_ }) -join ','))
            }
        } finally { $writer.Dispose() }
        $generated++
    }
    if ($generated -eq 0) { throw 'No readable worksheets were found.' }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
}
