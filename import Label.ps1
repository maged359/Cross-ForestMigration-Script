<#
====================================================================
 import.ps1 : CREATE LABELS + APPLY ENCRYPTION + CREATE POLICIES
====================================================================
 Imports into TENANT B (destination) from the enhanced export.ps1
 output. Does the COMPLETE job in one run:
   1. Creates labels (parents first) - drops RMS presets, de-dupes,
      skips existing, enforces tooltips.
   2. APPLIES ENCRYPTION / ACCESS PERMISSIONS using the clean
      EncryptionRightsDefinitions captured by export.ps1, remapping
      each identity onto the Tenant B domain.
   3. Creates label policies (user/group scoping remapped).

 Module : ExchangeOnlineManagement (Security & Compliance PowerShell)
 Auth   : Compliance Administrator of TENANT B (destination).

 REQUIREMENTS:
   - Tenant B must be LICENSED for sensitivity labels (E5/E5 Compliance
     or trial) - otherwise New-Label throws InvalidLicenseException.
   - The users/groups referenced by rights must already exist in
     Tenant B (from your user/group migration scripts).

 RUN IN POWERSHELL 7 (pwsh).

 Usage:
   pwsh
   .\import.ps1 -WhatIf            # preview everything
   .\import.ps1                    # create labels + encryption + policies
   .\import.ps1 -SkipEncryption    # labels + policies only (no protection)
====================================================================
#>

param(
    [switch]$WhatIf,
    [switch]$SkipEncryption
)

# ---- CONFIG -------------------------------------------------------
$AdminUPN     = "admin@m365x18449975.onmicrosoft.com"   # Tenant B compliance admin
$InFolder     = ".\LabelExport"
$TargetDomain = "m365x18449975.onmicrosoft.com"         # Tenant B verified domain
$LogPath      = ".\LabelExport\TenantB_Import_Log.csv"
# -------------------------------------------------------------------

Import-Module ExchangeOnlineManagement
Connect-IPPSSession -UserPrincipalName $AdminUPN
Write-Host "Connected to Tenant B Security & Compliance." -ForegroundColor Cyan

$rawLabels = @(Get-Content "$InFolder\labels.json" -Raw | ConvertFrom-Json)

$rawPolicies = @()
if (Test-Path "$InFolder\label-policies.json") {
    try   { $rawPolicies = @(Get-Content "$InFolder\label-policies.json" -Raw | ConvertFrom-Json) }
    catch { Write-Host "WARN: label-policies.json unparseable. Skipping policies." -ForegroundColor Yellow }
}

# ------- identity remap helper -------
function Remap-Identity([string]$id) {
    if ([string]::IsNullOrWhiteSpace($id)) { return $id }
    $reserved = @("AuthenticatedUsers","IPC_USER_ID_OWNER","All Authenticated Users")
    if ($reserved -contains $id) { return $id }
    if ($id -match "@")      { return (($id -split "@")[0]) + "@" + $TargetDomain }
    elseif ($id -match "\.") { return $TargetDomain }
    return $id
}
function Remap-Locations($loc) {
    if (-not $loc) { return @() }
    return @($loc | ForEach-Object {
        if ($_ -match "@") { (($_ -split "@")[0]) + "@" + $TargetDomain } else { $_ }
    })
}

# ------- CLEAN label set: drop RMS presets, empties, duplicates -------
$rmsPresetExact = @(
    "Anyone (unrestricted)","All Employees (unrestricted)","All Employees",
    "Trusted People","Specified People","Anyone",
    "Co-Author","Co-Owner","Reviewer","Viewer"
)
$rmsPresetPattern = '(?i)\(unrestricted\)|^Trusted People$|^Specified People$|^Anyone$|^All Employees$'

$seen = @{}
$labels = foreach ($l in $rawLabels) {
    if ([string]::IsNullOrWhiteSpace($l.DisplayName)) { continue }
    if ($rmsPresetExact -contains $l.DisplayName) {
        Write-Host ("DROP (RMS preset): {0}" -f $l.DisplayName) -ForegroundColor DarkGray; continue
    }
    if ($l.DisplayName -match $rmsPresetPattern) {
        Write-Host ("DROP (RMS preset): {0}" -f $l.DisplayName) -ForegroundColor DarkGray; continue
    }
    if ($seen.ContainsKey($l.DisplayName)) { continue }
    $seen[$l.DisplayName] = $true
    $l
}

# preload existing Tenant B labels
$existingByName = @{}; $existingByDisplay = @{}
Get-Label -ErrorAction SilentlyContinue | ForEach-Object {
    $existingByName[$_.Name] = $_.Name; $existingByDisplay[$_.DisplayName] = $_.Name
}

Write-Host ("Processing {0} real labels." -f @($labels).Count) -ForegroundColor Yellow
$labelNameMap = @{}; $log = @()

# ==================================================================
# 1) CREATE LABELS  +  2) APPLY ENCRYPTION
# ==================================================================
$ordered = $labels | Sort-Object @{ E = { if ($_.ParentId) { 1 } else { 0 } } }, Priority

foreach ($l in $ordered) {

    $internalName = ($l.DisplayName -replace '[^a-zA-Z0-9]', '')
    if ([string]::IsNullOrWhiteSpace($internalName)) {
        $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Label"; Status="Skipped-EmptyName"; Detail="" }; continue
    }
    if ($internalName.Length -gt 60) { $internalName = $internalName.Substring(0,60) }

    $labelIdentity = $null

    # ---- create (or skip if exists) ----
    if ($existingByDisplay.ContainsKey($l.DisplayName) -or $existingByName.ContainsKey($internalName)) {
        Write-Host ("SKIP (exists): {0}" -f $l.DisplayName) -ForegroundColor DarkYellow
        $labelNameMap[$l.DisplayName] = if ($existingByDisplay[$l.DisplayName]) { $existingByDisplay[$l.DisplayName] } else { $internalName }
        $labelIdentity = $l.DisplayName
        $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Label"; Status="Skipped-Exists"; Detail="" }
    }
    else {
        $tooltip = if ([string]::IsNullOrWhiteSpace($l.Tooltip)) { "$($l.DisplayName) sensitivity label" } else { $l.Tooltip }
        $params = @{ DisplayName=$l.DisplayName; Name=$internalName; Tooltip=$tooltip }
        if ($l.Comment) { $params.Comment = $l.Comment }
        if ($l.ApplyContentMarkingHeaderEnabled) {
            $params.ApplyContentMarkingHeaderEnabled = $true
            if ($l.ApplyContentMarkingHeaderText) { $params.ApplyContentMarkingHeaderText = $l.ApplyContentMarkingHeaderText }
        }
        if ($l.ApplyContentMarkingFooterEnabled) {
            $params.ApplyContentMarkingFooterEnabled = $true
            if ($l.ApplyContentMarkingFooterText) { $params.ApplyContentMarkingFooterText = $l.ApplyContentMarkingFooterText }
        }
        if ($l.ApplyWaterMarkingEnabled) {
            $params.ApplyWaterMarkingEnabled = $true
            if ($l.ApplyWaterMarkingText) { $params.ApplyWaterMarkingText = $l.ApplyWaterMarkingText }
        }
        if ($l.ParentId) {
            $parent = $labels | Where-Object { $_.Guid -eq $l.ParentId } | Select-Object -First 1
            if ($parent -and $labelNameMap[$parent.DisplayName]) { $params.ParentId = $labelNameMap[$parent.DisplayName] }
        }

        if ($WhatIf) {
            Write-Host ("WHATIF create: {0}" -f $l.DisplayName) -ForegroundColor Gray
            $labelNameMap[$l.DisplayName] = $internalName
        }
        else {
            try {
                $new = New-Label @params -ErrorAction Stop
                $labelNameMap[$l.DisplayName] = $new.Name
                $existingByName[$new.Name] = $new.Name; $existingByDisplay[$l.DisplayName] = $new.Name
                $labelIdentity = $new.Identity
                Write-Host ("CREATED label : {0}" -f $l.DisplayName) -ForegroundColor Green
                $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Label"; Status="Created"; Detail="" }
            }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match "AlreadyExists" -or $msg -match "DisplayNameConflict") {
                    Write-Host ("SKIP (exists): {0}" -f $l.DisplayName) -ForegroundColor DarkYellow
                    $labelNameMap[$l.DisplayName] = $internalName; $labelIdentity = $l.DisplayName
                    $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Label"; Status="Skipped-Exists"; Detail="" }
                } else {
                    Write-Host ("FAILED label  : {0}  -->  {1}" -f $l.DisplayName, $msg) -ForegroundColor Red
                    $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Label"; Status="Failed"; Detail=$msg }
                    continue
                }
            }
        }
    }

    # ---- APPLY ENCRYPTION / ACCESS PERMISSIONS ----
    if (-not $SkipEncryption -and $l.EncryptionEnabled) {

        # build remapped rights string:  id:RIGHTS;id2:RIGHTS2
        $pairs = @()
        foreach ($r in $l.EncryptionRightsDefinitions) {
            if ($r.Identity -and $r.Rights) {
                $pairs += ("{0}:{1}" -f (Remap-Identity $r.Identity), $r.Rights)
            }
        }
        $rightsString = ($pairs -join ";")

        $encParams = @{
            Identity          = if ($labelIdentity) { $labelIdentity } else { $l.DisplayName }
            EncryptionEnabled = $true
        }
        $encParams.EncryptionProtectionType = if ($l.EncryptionProtectionType) { $l.EncryptionProtectionType } else { "Template" }
        if ($rightsString)               { $encParams.EncryptionRightsDefinitions = $rightsString }
        if ($l.EncryptionOfflineAccessDays) { $encParams.EncryptionOfflineAccessDays = [int]$l.EncryptionOfflineAccessDays }
        if ($l.EncryptionContentExpiry)  { $encParams.EncryptionContentExpiredOnDateInDaysOrNever = $l.EncryptionContentExpiry }
        if ($l.EncryptionDoNotForward)   { $encParams.EncryptionDoNotForward = $true }
        if ($l.EncryptionEncryptOnly)    { $encParams.EncryptionEncryptOnly  = $true }

        if ($WhatIf) {
            Write-Host ("   WHATIF encrypt: {0}  rights=[{1}]" -f $l.DisplayName, $rightsString) -ForegroundColor DarkGray
        }
        else {
            try {
                Set-Label @encParams -ErrorAction Stop
                Write-Host ("   ENCRYPTED: {0}  rights=[{1}]" -f $l.DisplayName, $rightsString) -ForegroundColor Green
                $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Encryption"; Status="Applied"; Detail=$rightsString }
            }
            catch {
                Write-Host ("   ENCRYPT FAILED: {0}  -->  {1}" -f $l.DisplayName, $_.Exception.Message) -ForegroundColor Red
                $log += [pscustomobject]@{ Item=$l.DisplayName; Type="Encryption"; Status="Failed"; Detail=$_.Exception.Message }
            }
        }
    }
}

# ==================================================================
# 3) CREATE LABEL POLICIES
# ==================================================================
foreach ($p in $rawPolicies) {
    if ([string]::IsNullOrWhiteSpace($p.Name)) { continue }

    if (Get-LabelPolicy -Identity $p.Name -ErrorAction SilentlyContinue) {
        Write-Host ("SKIP policy (exists): {0}" -f $p.Name) -ForegroundColor DarkYellow
        $log += [pscustomobject]@{ Item=$p.Name; Type="Policy"; Status="Skipped-Exists"; Detail="" }; continue
    }

    $labelNames = @($p.Labels | ForEach-Object { if ($labelNameMap[$_]) { $labelNameMap[$_] } else { $_ } }) | Where-Object { $_ }
    if (-not $labelNames -or $labelNames.Count -eq 0) {
        Write-Host ("SKIP policy (no labels): {0}" -f $p.Name) -ForegroundColor DarkYellow
        $log += [pscustomobject]@{ Item=$p.Name; Type="Policy"; Status="Skipped-NoLabels"; Detail="" }; continue
    }

    $params = @{ Name=$p.Name; Labels=$labelNames }
    if ($p.Comment) { $params.Comment = $p.Comment }
    $ex=Remap-Locations $p.ExchangeLocation; $spo=Remap-Locations $p.SharePointLocation
    $od=Remap-Locations $p.OneDriveLocation; $grp=Remap-Locations $p.ModernGroupLocation
    if ($ex.Count)  { $params.ExchangeLocation   = $ex }
    if ($spo.Count) { $params.SharePointLocation  = $spo }
    if ($od.Count)  { $params.OneDriveLocation    = $od }
    if ($grp.Count) { $params.ModernGroupLocation = $grp }

    if ($WhatIf) {
        Write-Host ("WHATIF create policy: {0}" -f $p.Name) -ForegroundColor Gray; continue
    }
    try {
        New-LabelPolicy @params -ErrorAction Stop | Out-Null
        Write-Host ("CREATED policy : {0}" -f $p.Name) -ForegroundColor Green
        $log += [pscustomobject]@{ Item=$p.Name; Type="Policy"; Status="Created"; Detail="" }
    }
    catch {
        Write-Host ("FAILED policy  : {0}  -->  {1}" -f $p.Name, $_.Exception.Message) -ForegroundColor Red
        $log += [pscustomobject]@{ Item=$p.Name; Type="Policy"; Status="Failed"; Detail=$_.Exception.Message }
    }
}

if (-not $WhatIf) {
    $log | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
    Write-Host ("`nDone. Log: {0}" -f (Resolve-Path $LogPath)) -ForegroundColor Cyan
}

Write-Host "`nVERIFY in Purview portal: labels, assigned users/rights, and policy scoping." -ForegroundColor Yellow
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
