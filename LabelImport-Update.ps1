<#
====================================================================
 import.ps1 : LABELS + ENCRYPTION + CONTENT MARKING + STATIC &
              DYNAMIC WATERMARK + CLIENT-SIDE AUTO-LABELING + POLICIES
====================================================================
 Applies EVERYTHING from export.ps1:
   1. Create labels (parents first; drop RMS presets; de-dupe; skip
      existing; enforce tooltips) + content marking + static watermark.
   2. Apply ENCRYPTION / access permissions (identities remapped).
   3. Apply DYNAMIC WATERMARK (needs encryption; applied after it).
   4. Apply CLIENT-SIDE AUTO-LABELING conditions (Set-Label
      -Conditions with the exported JSON).                    <-- NEW
   5. Create label policies (scoping remapped).

 Module : ExchangeOnlineManagement (Security & Compliance PowerShell)
 Auth   : Compliance Administrator of TENANT B (destination).
 RUN IN POWERSHELL 7 (pwsh).

 IMPORTANT for AUTO-LABELING conditions:
   - Conditions reference SENSITIVE INFO TYPES (SITs) by GUID.
   - BUILT-IN SITs share the same GUID across tenants -> port cleanly.
   - CUSTOM SITs have tenant-specific GUIDs -> you must recreate the
     custom SIT in Tenant B FIRST (ideally same GUID) or the condition
     apply will fail. The script logs any such failures for follow-up.

 Usage:
   pwsh
   .\import.ps1 -WhatIf
   .\import.ps1
   .\import.ps1 -SkipEncryption   # skip encryption + dynamic WM
   .\import.ps1 -SkipAutoLabeling # skip client-side auto-label conditions
====================================================================
#>

param(
    [switch]$WhatIf,
    [switch]$SkipEncryption,
    [switch]$SkipAutoLabeling
)

# ---- CONFIG -------------------------------------------------------
$AdminUPN     = "admin@m365x18449975.onmicrosoft.com"
$InFolder     = ".\LabelExport"
$TargetDomain = "m365x18449975.onmicrosoft.com"
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
    return @($loc | ForEach-Object { if ($_ -match "@") { (($_ -split "@")[0]) + "@" + $TargetDomain } else { $_ } })
}

# clean label set
$rmsPresetExact = @("Anyone (unrestricted)","All Employees (unrestricted)","All Employees","Trusted People","Specified People","Anyone","Co-Author","Co-Owner","Reviewer","Viewer")
$rmsPresetPattern = '(?i)\(unrestricted\)|^Trusted People$|^Specified People$|^Anyone$|^All Employees$'
$seen=@{}
$labels = foreach ($l in $rawLabels) {
    if ([string]::IsNullOrWhiteSpace($l.DisplayName)) { continue }
    if ($rmsPresetExact -contains $l.DisplayName -or $l.DisplayName -match $rmsPresetPattern) { Write-Host ("DROP (RMS preset): {0}" -f $l.DisplayName) -ForegroundColor DarkGray; continue }
    if ($seen.ContainsKey($l.DisplayName)) { continue }
    $seen[$l.DisplayName]=$true; $l
}

$existingByName=@{}; $existingByDisplay=@{}
Get-Label -ErrorAction SilentlyContinue | ForEach-Object { $existingByName[$_.Name]=$_.Name; $existingByDisplay[$_.DisplayName]=$_.Name }

Write-Host ("Processing {0} real labels." -f @($labels).Count) -ForegroundColor Yellow
$labelNameMap=@{}; $log=@()

$ordered = $labels | Sort-Object @{ E = { if ($_.ParentId) {1} else {0} } }, Priority

foreach ($l in $ordered) {

    $internalName = ($l.DisplayName -replace '[^a-zA-Z0-9]','')
    if ([string]::IsNullOrWhiteSpace($internalName)) { $log += [pscustomobject]@{Item=$l.DisplayName;Type="Label";Status="Skipped-EmptyName";Detail=""}; continue }
    if ($internalName.Length -gt 60) { $internalName=$internalName.Substring(0,60) }

    $labelIdentity=$null

    # ---------- CREATE label (+ content marking + static watermark) ----------
    if ($existingByDisplay.ContainsKey($l.DisplayName) -or $existingByName.ContainsKey($internalName)) {
        Write-Host ("SKIP (exists): {0}" -f $l.DisplayName) -ForegroundColor DarkYellow
        $labelNameMap[$l.DisplayName]= if ($existingByDisplay[$l.DisplayName]){$existingByDisplay[$l.DisplayName]}else{$internalName}
        $labelIdentity=$l.DisplayName
        $log += [pscustomobject]@{Item=$l.DisplayName;Type="Label";Status="Skipped-Exists";Detail=""}
    }
    else {
        $tooltip = if ([string]::IsNullOrWhiteSpace($l.Tooltip)) { "$($l.DisplayName) sensitivity label" } else { $l.Tooltip }
        $params=@{ DisplayName=$l.DisplayName; Name=$internalName; Tooltip=$tooltip }
        if ($l.Comment){$params.Comment=$l.Comment}
        if ($l.HeaderEnabled){ $params.ApplyContentMarkingHeaderEnabled=$true
            if($l.HeaderText){$params.ApplyContentMarkingHeaderText=$l.HeaderText}; if($l.HeaderFontName){$params.ApplyContentMarkingHeaderFontName=$l.HeaderFontName}
            if($l.HeaderFontSize){$params.ApplyContentMarkingHeaderFontSize=[int]$l.HeaderFontSize}; if($l.HeaderFontColor){$params.ApplyContentMarkingHeaderFontColor=$l.HeaderFontColor}
            if($l.HeaderAlignment){$params.ApplyContentMarkingHeaderAlignment=$l.HeaderAlignment}; if($l.HeaderMargin){$params.ApplyContentMarkingHeaderMargin=[int]$l.HeaderMargin} }
        if ($l.FooterEnabled){ $params.ApplyContentMarkingFooterEnabled=$true
            if($l.FooterText){$params.ApplyContentMarkingFooterText=$l.FooterText}; if($l.FooterFontName){$params.ApplyContentMarkingFooterFontName=$l.FooterFontName}
            if($l.FooterFontSize){$params.ApplyContentMarkingFooterFontSize=[int]$l.FooterFontSize}; if($l.FooterFontColor){$params.ApplyContentMarkingFooterFontColor=$l.FooterFontColor}
            if($l.FooterAlignment){$params.ApplyContentMarkingFooterAlignment=$l.FooterAlignment}; if($l.FooterMargin){$params.ApplyContentMarkingFooterMargin=[int]$l.FooterMargin} }
        if ($l.WatermarkEnabled){ $params.ApplyWaterMarkingEnabled=$true
            if($l.WatermarkText){$params.ApplyWaterMarkingText=$l.WatermarkText}; if($l.WatermarkFontName){$params.ApplyWaterMarkingFontName=$l.WatermarkFontName}
            if($l.WatermarkFontSize){$params.ApplyWaterMarkingFontSize=[int]$l.WatermarkFontSize}; if($l.WatermarkFontColor){$params.ApplyWaterMarkingFontColor=$l.WatermarkFontColor}
            if($l.WatermarkLayout){$params.ApplyWaterMarkingLayout=$l.WatermarkLayout} }
        if ($l.ParentId){ $parent=$labels | Where-Object { $_.Guid -eq $l.ParentId } | Select-Object -First 1
            if ($parent -and $labelNameMap[$parent.DisplayName]){ $params.ParentId=$labelNameMap[$parent.DisplayName] } }

        if ($WhatIf){
            Write-Host ("WHATIF create: {0} (H={1} F={2} W={3} DynWM={4} Auto={5})" -f $l.DisplayName,$l.HeaderEnabled,$l.FooterEnabled,$l.WatermarkEnabled,$l.DynamicWatermarkEnabled,$l.AutoLabelingEnabled) -ForegroundColor Gray
            $labelNameMap[$l.DisplayName]=$internalName
        }
        else {
            try {
                $new=New-Label @params -ErrorAction Stop
                $labelNameMap[$l.DisplayName]=$new.Name; $existingByName[$new.Name]=$new.Name; $existingByDisplay[$l.DisplayName]=$new.Name
                $labelIdentity=$new.Identity
                $marks=@(); if($l.HeaderEnabled){$marks+="Header"}; if($l.FooterEnabled){$marks+="Footer"}; if($l.WatermarkEnabled){$marks+="Watermark"}
                Write-Host ("CREATED label : {0}  [{1}]" -f $l.DisplayName,($marks -join "+")) -ForegroundColor Green
                $log += [pscustomobject]@{Item=$l.DisplayName;Type="Label";Status="Created";Detail=($marks -join "+")}
            }
            catch {
                $msg=$_.Exception.Message
                if ($msg -match "AlreadyExists" -or $msg -match "DisplayNameConflict"){
                    Write-Host ("SKIP (exists): {0}" -f $l.DisplayName) -ForegroundColor DarkYellow
                    $labelNameMap[$l.DisplayName]=$internalName; $labelIdentity=$l.DisplayName
                    $log += [pscustomobject]@{Item=$l.DisplayName;Type="Label";Status="Skipped-Exists";Detail=""}
                } else {
                    Write-Host ("FAILED label  : {0}  -->  {1}" -f $l.DisplayName,$msg) -ForegroundColor Red
                    $log += [pscustomobject]@{Item=$l.DisplayName;Type="Label";Status="Failed";Detail=$msg}; continue
                }
            }
        }
    }

    # ---------- APPLY ENCRYPTION ----------
    $encryptionApplied=$false
    if (-not $SkipEncryption -and $l.EncryptionEnabled) {
        $pairs=@()
        foreach ($r in $l.EncryptionRightsDefinitions){ if ($r.Identity -and $r.Rights){ $pairs += ("{0}:{1}" -f (Remap-Identity $r.Identity), $r.Rights) } }
        $rightsString=($pairs -join ";")
        $encParams=@{ Identity= if($labelIdentity){$labelIdentity}else{$l.DisplayName}; EncryptionEnabled=$true }
        $encParams.EncryptionProtectionType= if($l.EncryptionProtectionType){$l.EncryptionProtectionType}else{"Template"}
        if ($rightsString){$encParams.EncryptionRightsDefinitions=$rightsString}
        if ($l.EncryptionOfflineAccessDays){$encParams.EncryptionOfflineAccessDays=[int]$l.EncryptionOfflineAccessDays}
        if ($l.EncryptionContentExpiry){$encParams.EncryptionContentExpiredOnDateInDaysOrNever=$l.EncryptionContentExpiry}
        if ($l.EncryptionDoNotForward){$encParams.EncryptionDoNotForward=$true}
        if ($l.EncryptionEncryptOnly){$encParams.EncryptionEncryptOnly=$true}

        if ($WhatIf){ Write-Host ("   WHATIF encrypt: rights=[{0}]" -f $rightsString) -ForegroundColor DarkGray; $encryptionApplied=$true }
        else {
            try { Set-Label @encParams -ErrorAction Stop
                  Write-Host ("   ENCRYPTED: rights=[{0}]" -f $rightsString) -ForegroundColor Green; $encryptionApplied=$true
                  $log += [pscustomobject]@{Item=$l.DisplayName;Type="Encryption";Status="Applied";Detail=$rightsString} }
            catch { Write-Host ("   ENCRYPT FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
                  $log += [pscustomobject]@{Item=$l.DisplayName;Type="Encryption";Status="Failed";Detail=$_.Exception.Message} }
        }
    }

    # ---------- APPLY CONTENT MARKING / STATIC WATERMARK to existing/skipped ----------
    if ($labelIdentity -and ($l.HeaderEnabled -or $l.FooterEnabled -or $l.WatermarkEnabled)) {
        $mk=@{ Identity=$labelIdentity }
        if ($l.HeaderEnabled){ $mk.ApplyContentMarkingHeaderEnabled=$true
            if($l.HeaderText){$mk.ApplyContentMarkingHeaderText=$l.HeaderText}; if($l.HeaderFontName){$mk.ApplyContentMarkingHeaderFontName=$l.HeaderFontName}
            if($l.HeaderFontSize){$mk.ApplyContentMarkingHeaderFontSize=[int]$l.HeaderFontSize}; if($l.HeaderFontColor){$mk.ApplyContentMarkingHeaderFontColor=$l.HeaderFontColor}
            if($l.HeaderAlignment){$mk.ApplyContentMarkingHeaderAlignment=$l.HeaderAlignment}; if($l.HeaderMargin){$mk.ApplyContentMarkingHeaderMargin=[int]$l.HeaderMargin} }
        if ($l.FooterEnabled){ $mk.ApplyContentMarkingFooterEnabled=$true
            if($l.FooterText){$mk.ApplyContentMarkingFooterText=$l.FooterText}; if($l.FooterFontName){$mk.ApplyContentMarkingFooterFontName=$l.FooterFontName}
            if($l.FooterFontSize){$mk.ApplyContentMarkingFooterFontSize=[int]$l.FooterFontSize}; if($l.FooterFontColor){$mk.ApplyContentMarkingFooterFontColor=$l.FooterFontColor}
            if($l.FooterAlignment){$mk.ApplyContentMarkingFooterAlignment=$l.FooterAlignment}; if($l.FooterMargin){$mk.ApplyContentMarkingFooterMargin=[int]$l.FooterMargin} }
        if ($l.WatermarkEnabled){ $mk.ApplyWaterMarkingEnabled=$true
            if($l.WatermarkText){$mk.ApplyWaterMarkingText=$l.WatermarkText}; if($l.WatermarkFontName){$mk.ApplyWaterMarkingFontName=$l.WatermarkFontName}
            if($l.WatermarkFontSize){$mk.ApplyWaterMarkingFontSize=[int]$l.WatermarkFontSize}; if($l.WatermarkFontColor){$mk.ApplyWaterMarkingFontColor=$l.WatermarkFontColor}
            if($l.WatermarkLayout){$mk.ApplyWaterMarkingLayout=$l.WatermarkLayout} }

        if ($WhatIf){ Write-Host ("   WHATIF marking: H={0} F={1} W={2}" -f $l.HeaderEnabled,$l.FooterEnabled,$l.WatermarkEnabled) -ForegroundColor DarkGray }
        else {
            try { Set-Label @mk -ErrorAction Stop
                  Write-Host ("   MARKING applied (H={0} F={1} W={2})" -f $l.HeaderEnabled,$l.FooterEnabled,$l.WatermarkEnabled) -ForegroundColor Green
                  $log += [pscustomobject]@{Item=$l.DisplayName;Type="Marking";Status="Applied";Detail="H=$($l.HeaderEnabled);F=$($l.FooterEnabled);W=$($l.WatermarkEnabled)"} }
            catch { Write-Host ("   MARKING FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
                  $log += [pscustomobject]@{Item=$l.DisplayName;Type="Marking";Status="Failed";Detail=$_.Exception.Message} }
        }
    }

    # ---------- APPLY DYNAMIC WATERMARK (requires encryption) ----------
    if ($l.DynamicWatermarkEnabled -and $labelIdentity) {
        if (-not $encryptionApplied -and -not $WhatIf) {
            Write-Host ("   DYN-WM SKIPPED (needs encryption): {0}" -f $l.DisplayName) -ForegroundColor DarkYellow
            $log += [pscustomobject]@{Item=$l.DisplayName;Type="DynamicWM";Status="Skipped-NoEncryption";Detail=""}
        } else {
            $dw=@{ Identity=$labelIdentity; ApplyDynamicWatermarkingEnabled=$true }
            if ($l.DynamicWatermarkDisplay){ $dw.DynamicWatermarkDisplay=$l.DynamicWatermarkDisplay }
            if ($WhatIf){ Write-Host ("   WHATIF dynamic watermark: display=[{0}]" -f $l.DynamicWatermarkDisplay) -ForegroundColor DarkGray }
            else {
                try { Set-Label @dw -ErrorAction Stop
                      Write-Host ("   DYNAMIC WATERMARK applied: display=[{0}]" -f $l.DynamicWatermarkDisplay) -ForegroundColor Green
                      $log += [pscustomobject]@{Item=$l.DisplayName;Type="DynamicWM";Status="Applied";Detail=$l.DynamicWatermarkDisplay} }
                catch { Write-Host ("   DYN-WM FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
                      $log += [pscustomobject]@{Item=$l.DisplayName;Type="DynamicWM";Status="Failed";Detail=$_.Exception.Message} }
            }
        }
    }

    # ---------- APPLY CLIENT-SIDE AUTO-LABELING CONDITIONS ----------
    if (-not $SkipAutoLabeling -and $l.AutoLabelingEnabled -and $l.ConditionsJson -and $labelIdentity) {
        if ($WhatIf){
            Write-Host ("   WHATIF auto-label conditions ({0})" -f $l.AutoApplyType) -ForegroundColor DarkGray
        } else {
            try {
                Set-Label -Identity $labelIdentity -Conditions $l.ConditionsJson -ErrorAction Stop
                Write-Host ("   AUTO-LABELING applied ({0})" -f $l.AutoApplyType) -ForegroundColor Green
                $log += [pscustomobject]@{Item=$l.DisplayName;Type="AutoLabeling";Status="Applied";Detail=$l.AutoApplyType}
            }
            catch {
                Write-Host ("   AUTO-LABELING FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
                Write-Host ("      (If this references a CUSTOM SIT, recreate it in Tenant B first.)" ) -ForegroundColor DarkYellow
                $log += [pscustomobject]@{Item=$l.DisplayName;Type="AutoLabeling";Status="Failed";Detail=$_.Exception.Message}
            }
        }
    }
}

# ==================================================================
# CREATE LABEL POLICIES
# ==================================================================
foreach ($p in $rawPolicies) {
    if ([string]::IsNullOrWhiteSpace($p.Name)) { continue }
    if (Get-LabelPolicy -Identity $p.Name -ErrorAction SilentlyContinue) {
        Write-Host ("SKIP policy (exists): {0}" -f $p.Name) -ForegroundColor DarkYellow
        $log += [pscustomobject]@{Item=$p.Name;Type="Policy";Status="Skipped-Exists";Detail=""}; continue
    }
    $labelNames=@($p.Labels | ForEach-Object { if ($labelNameMap[$_]){$labelNameMap[$_]}else{$_} }) | Where-Object { $_ }
    if (-not $labelNames -or $labelNames.Count -eq 0) {
        Write-Host ("SKIP policy (no labels): {0}" -f $p.Name) -ForegroundColor DarkYellow
        $log += [pscustomobject]@{Item=$p.Name;Type="Policy";Status="Skipped-NoLabels";Detail=""}; continue
    }
    $params=@{ Name=$p.Name; Labels=$labelNames }
    if ($p.Comment){$params.Comment=$p.Comment}
    $ex=Remap-Locations $p.ExchangeLocation; $spo=Remap-Locations $p.SharePointLocation
    $od=Remap-Locations $p.OneDriveLocation; $grp=Remap-Locations $p.ModernGroupLocation
    if ($ex.Count){$params.ExchangeLocation=$ex}; if ($spo.Count){$params.SharePointLocation=$spo}
    if ($od.Count){$params.OneDriveLocation=$od}; if ($grp.Count){$params.ModernGroupLocation=$grp}

    if ($WhatIf){ Write-Host ("WHATIF create policy: {0}" -f $p.Name) -ForegroundColor Gray; continue }
    try { New-LabelPolicy @params -ErrorAction Stop | Out-Null
          Write-Host ("CREATED policy : {0}" -f $p.Name) -ForegroundColor Green
          $log += [pscustomobject]@{Item=$p.Name;Type="Policy";Status="Created";Detail=""} }
    catch { Write-Host ("FAILED policy  : {0}  -->  {1}" -f $p.Name,$_.Exception.Message) -ForegroundColor Red
          $log += [pscustomobject]@{Item=$p.Name;Type="Policy";Status="Failed";Detail=$_.Exception.Message} }
}

if (-not $WhatIf) {
    $log | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
    Write-Host ("`nDone. Log: {0}" -f (Resolve-Path $LogPath)) -ForegroundColor Cyan
}
Write-Host "`nVERIFY in Purview: encryption, marking, static + dynamic watermark, auto-labeling conditions, policies." -ForegroundColor Yellow
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
