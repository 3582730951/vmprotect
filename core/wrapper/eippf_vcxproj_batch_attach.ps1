param(
    [string]$Root = ".",
    [string]$PropsPath = "",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RelativePathSafe {
    param(
        [Parameter(Mandatory = $true)][string]$FromDir,
        [Parameter(Mandatory = $true)][string]$ToPath
    )
    $fromUri = New-Object System.Uri(($FromDir.TrimEnd('\') + '\'))
    $toUri = New-Object System.Uri($ToPath)
    $rel = $fromUri.MakeRelativeUri($toUri).ToString()
    return [System.Uri]::UnescapeDataString($rel).Replace('/', '\')
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path

if ([string]::IsNullOrWhiteSpace($PropsPath)) {
    $PropsPath = Join-Path $repoRoot "core\docs\eippf_vcxproj_integration.props"
}

$rootFull = (Resolve-Path $Root).Path
$propsFull = (Resolve-Path $PropsPath).Path

if (-not (Test-Path -LiteralPath $propsFull)) {
    throw "Props file not found: $propsFull"
}

$projects = Get-ChildItem -LiteralPath $rootFull -Recurse -Filter *.vcxproj -File
if ($projects.Count -eq 0) {
    Write-Host "[EIPPF] No .vcxproj found under: $rootFull"
    exit 0
}

$updated = 0
$skipped = 0

foreach ($proj in $projects) {
    [xml]$xml = Get-Content -LiteralPath $proj.FullName
    $nsUri = $xml.Project.NamespaceURI
    $nsmgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)

    if ([string]::IsNullOrWhiteSpace($nsUri)) {
        $projectNode = $xml.SelectSingleNode("//Project")
        $importNodes = $xml.SelectNodes("//Import[contains(@Project,'eippf_vcxproj_integration.props')]")
        $groupNodes = $xml.SelectNodes("//ImportGroup[@Label='PropertySheets']")
    } else {
        $nsmgr.AddNamespace("msb", $nsUri)
        $projectNode = $xml.SelectSingleNode("//msb:Project", $nsmgr)
        $importNodes = $xml.SelectNodes("//msb:Import[contains(@Project,'eippf_vcxproj_integration.props')]", $nsmgr)
        $groupNodes = $xml.SelectNodes("//msb:ImportGroup[@Label='PropertySheets']", $nsmgr)
    }

    if ($null -eq $projectNode) {
        Write-Host "[EIPPF] Skip (invalid vcxproj): $($proj.FullName)"
        $skipped++
        continue
    }

    if ($importNodes.Count -gt 0) {
        Write-Host "[EIPPF] Already configured: $($proj.FullName)"
        $skipped++
        continue
    }

    $projDir = Split-Path -Parent $proj.FullName
    $relativeProps = Get-RelativePathSafe -FromDir $projDir -ToPath $propsFull

    if ($groupNodes.Count -gt 0) {
        $targetGroup = $groupNodes.Item(0)
    } else {
        if ([string]::IsNullOrWhiteSpace($nsUri)) {
            $targetGroup = $xml.CreateElement("ImportGroup")
        } else {
            $targetGroup = $xml.CreateElement("ImportGroup", $nsUri)
        }
        [void]$targetGroup.SetAttribute("Label", "PropertySheets")
        [void]$projectNode.AppendChild($targetGroup)
    }

    if ([string]::IsNullOrWhiteSpace($nsUri)) {
        $import = $xml.CreateElement("Import")
    } else {
        $import = $xml.CreateElement("Import", $nsUri)
    }
    [void]$import.SetAttribute("Project", $relativeProps)
    [void]$import.SetAttribute("Condition", "Exists('$relativeProps')")
    [void]$targetGroup.AppendChild($import)

    if ($DryRun.IsPresent) {
        Write-Host "[EIPPF][DRY-RUN] Would update: $($proj.FullName)"
        continue
    }

    $xml.Save($proj.FullName)
    Write-Host "[EIPPF] Updated: $($proj.FullName)"
    $updated++
}

Write-Host "[EIPPF] Done. updated=$updated skipped=$skipped root=$rootFull"
exit 0
