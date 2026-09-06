<#
====================================================================
 export.ps1 : FULL EXPORT OF SENSITIVITY LABELS + POLICIES
====================================================================
 Captures EVERYTHING needed to recreate labels in Tenant B:
   - Encryption / access rights (rightsdefinitions, offline, expiry,
     DNF, encrypt-only, protection type)
   - Content marking header/footer (text, font, size, color, align, margin)
   - Static watermark (text, font, size, color, layout)
   - DYNAMIC WATERMARK (enabled + custom display)           <-- FIXED
   - CLIENT-SIDE AUTO-LABELING (Conditions: SIT rules,
     autoapplytype Automatic/Recommend, policy tip)         <-- NEW

 NOTES:
   * Dynamic watermark: read directly from the label's top-level
     ApplyDynamicWatermarkingEnabled / DynamicWatermarkDisplay
     properties (most reliable) with a LabelActions fallback.
   * Client-side auto-labeling lives in the label's .Conditions
     property (JSON). We store it verbatim so it can be re-applied
     with Set-Label -Conditions. SIT GUIDs are portable (built-in
     SITs share GUIDs across tenants; CUSTOM SITs must be recreated
     in Tenant B first with the same GUID or the condition remapped).

 Module : ExchangeOnlineManagement (Security & Compliance PowerShell)
 Auth   : Compliance Administrator of TENANT A (source).
 RUN IN POWERSHELL 7 (pwsh).

 Setup:  Install-Module ExchangeOnlineManagement -MinimumVersion 3.4.0 -Scope CurrentUser
 Usage:  pwsh ; .\export.ps1
====================================================================
#>

# ---- CONFIG -------------------------------------------------------
$AdminUPN  = "admin@tenantA.onmicrosoft.com"
$OutFolder = ".\LabelExport"
# -------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $OutFolder | Out-Null
Import-Module ExchangeOnlineManagement
Connect-IPPSSession -UserPrincipalName $AdminUPN
Write-Host "Connected to Tenant A Security & Compliance." -ForegroundColor Cyan

function Get-SetVal($settings, $key) {
    foreach ($s in $settings) { if ("$($s.Key)".ToLower() -eq $key.ToLower()) { return "$($s.Value)" } }
    return $null
}

function Get-LabelActionInfo($label) {
    $info = [ordered]@{
        EncEnabled=$false; EncProtectionType=$null; EncOfflineDays=$null; EncExpiry=$null
        EncDoNotForward=$false; EncEncryptOnly=$false; EncRights=@()
        HdrEnabled=$false; HdrText=$null; HdrFontName=$null; HdrFontSize=$null; HdrFontColor=$null; HdrAlign=$null; HdrMargin=$null
        FtrEnabled=$false; FtrText=$null; FtrFontName=$null; FtrFontSize=$null; FtrFontColor=$null; FtrAlign=$null; FtrMargin=$null
        WmEnabled=$false; WmText=$null; WmFontName=$null; WmFontSize=$null; WmFontColor=$null; WmLayout=$null
        DynWmEnabled=$false; DynWmDisplay=$null
    }
    if (-not $label.LabelActions) { return $info }
    foreach ($actionRaw in $label.LabelActions) {
        $action = $actionRaw
        if ($actionRaw -is [string]) { try { $action = $actionRaw | ConvertFrom-Json } catch { continue } }
        $type="$($action.Type)".ToLower(); $subType="$($action.SubType)".ToLower(); $st=$action.Settings
        $disabled=(Get-SetVal $st "disabled"); $isOn = -not ($disabled -and $disabled.ToLower() -eq "true")
        switch ($type) {
            "encrypt" {
                $info.EncEnabled=$isOn
                $info.EncProtectionType=Get-SetVal $st "protectiontype"
                $info.EncOfflineDays=Get-SetVal $st "offlineaccessdays"
                $info.EncExpiry=Get-SetVal $st "contentexpiredondateindaysornever"
                $dnf=Get-SetVal $st "donotforward"; if ($dnf){$info.EncDoNotForward=($dnf.ToLower() -eq "true")}
                $eo=Get-SetVal $st "encryptonly";  if ($eo){$info.EncEncryptOnly=($eo.ToLower() -eq "true")}
                $rd=Get-SetVal $st "rightsdefinitions"
                if ($rd){ try { foreach ($r in ($rd | ConvertFrom-Json)){ $info.EncRights += [ordered]@{Identity=$r.Identity;Rights=$r.Rights} } } catch {} }
                $dwe=Get-SetVal $st "dynamicwatermarkdisplayenabled"; if(-not $dwe){$dwe=Get-SetVal $st "dynamicwatermarkingenabled"}
                if ($dwe){$info.DynWmEnabled=($dwe.ToLower() -eq "true")}
                $dwd=Get-SetVal $st "dynamicwatermarkdisplay"; if($dwd){$info.DynWmDisplay=$dwd}
            }
            "applycontentmarking" {
                if ($subType -eq "header"){ $info.HdrEnabled=$isOn
                    $info.HdrText=Get-SetVal $st "text"; $info.HdrFontName=Get-SetVal $st "fontname"; $info.HdrFontSize=Get-SetVal $st "fontsize"
                    $info.HdrFontColor=Get-SetVal $st "fontcolor"; $info.HdrAlign=Get-SetVal $st "alignment"; $info.HdrMargin=Get-SetVal $st "margin" }
                elseif ($subType -eq "footer"){ $info.FtrEnabled=$isOn
                    $info.FtrText=Get-SetVal $st "text"; $info.FtrFontName=Get-SetVal $st "fontname"; $info.FtrFontSize=Get-SetVal $st "fontsize"
                    $info.FtrFontColor=Get-SetVal $st "fontcolor"; $info.FtrAlign=Get-SetVal $st "alignment"; $info.FtrMargin=Get-SetVal $st "margin" }
            }
            "applywatermarking" {
                $info.WmEnabled=$isOn
                $info.WmText=Get-SetVal $st "text"; $info.WmFontName=Get-SetVal $st "fontname"; $info.WmFontSize=Get-SetVal $st "fontsize"
                $info.WmFontColor=Get-SetVal $st "fontcolor"; $info.WmLayout=Get-SetVal $st "layout"
                $dwe=Get-SetVal $st "dynamicwatermarkdisplayenabled"; if(-not $dwe){$dwe=Get-SetVal $st "dynamicwatermarkingenabled"}
                if ($dwe){$info.DynWmEnabled=($dwe.ToLower() -eq "true")}
                $dwd=Get-SetVal $st "dynamicwatermarkdisplay"; if($dwd){$info.DynWmDisplay=$dwd}
            }
        }
    }
    return $info
}

# ==================================================================
# 1) EXPORT LABELS
# ==================================================================
Write-Host "Exporting sensitivity labels..." -ForegroundColor Yellow
$rawLabels = @(Get-Label -IncludeDetailedLabelActions)

$labelsOut = foreach ($l in $rawLabels) {
    $a = Get-LabelActionInfo $l

    # --- Dynamic watermark: prefer reliable top-level properties ---
    $dynEnabled = $a.DynWmEnabled
    $dynDisplay = $a.DynWmDisplay
    if ($l.PSObject.Properties.Name -contains "ApplyDynamicWatermarkingEnabled" -and $l.ApplyDynamicWatermarkingEnabled) { $dynEnabled = $true }
    if ($l.PSObject.Properties.Name -contains "DynamicWatermarkDisplay" -and $l.DynamicWatermarkDisplay) { $dynDisplay = "$($l.DynamicWatermarkDisplay)" }

    # --- Client-side auto-labeling conditions (verbatim JSON) ---
    $conditionsJson = $null
    $autoApplyType  = $null
    if ($l.Conditions) {
        $conditionsJson = "$($l.Conditions)"      # store the raw JSON string
        # try to surface the autoapplytype for the audit CSV
        try {
            $cObj = $l.Conditions | ConvertFrom-Json
            $flat = ($l.Conditions)
            if ($flat -match '"autoapplytype"\s*:\s*"([^"]+)"') { $autoApplyType = $Matches[1] }
        } catch {}
    }

    [ordered]@{
        DisplayName=$l.DisplayName; Name=$l.Name; Guid="$($l.Guid)"; ParentId="$($l.ParentId)"
        Priority=$l.Priority; Tooltip=$l.Tooltip; Comment=$l.Comment; IsParent=[bool]$l.IsParent

        EncryptionEnabled=$a.EncEnabled; EncryptionProtectionType=$a.EncProtectionType
        EncryptionOfflineAccessDays=$a.EncOfflineDays; EncryptionContentExpiry=$a.EncExpiry
        EncryptionDoNotForward=$a.EncDoNotForward; EncryptionEncryptOnly=$a.EncEncryptOnly
        EncryptionRightsDefinitions=$a.EncRights

        HeaderEnabled=$a.HdrEnabled; HeaderText=$a.HdrText; HeaderFontName=$a.HdrFontName
        HeaderFontSize=$a.HdrFontSize; HeaderFontColor=$a.HdrFontColor; HeaderAlignment=$a.HdrAlign; HeaderMargin=$a.HdrMargin
        FooterEnabled=$a.FtrEnabled; FooterText=$a.FtrText; FooterFontName=$a.FtrFontName
        FooterFontSize=$a.FtrFontSize; FooterFontColor=$a.FtrFontColor; FooterAlignment=$a.FtrAlign; FooterMargin=$a.FtrMargin
        WatermarkEnabled=$a.WmEnabled; WatermarkText=$a.WmText; WatermarkFontName=$a.WmFontName
        WatermarkFontSize=$a.WmFontSize; WatermarkFontColor=$a.WmFontColor; WatermarkLayout=$a.WmLayout

        DynamicWatermarkEnabled=$dynEnabled
        DynamicWatermarkDisplay=$dynDisplay

        # ---- CLIENT-SIDE AUTO-LABELING ----
        AutoLabelingEnabled = [bool]$conditionsJson
        AutoApplyType       = $autoApplyType          # Automatic / Recommend
        ConditionsJson      = $conditionsJson         # raw JSON to re-apply
    }
}

$labelsOut | ConvertTo-Json -Depth 30 | Out-File "$OutFolder\labels.json" -Encoding UTF8
Write-Host ("Exported {0} labels" -f @($labelsOut).Count) -ForegroundColor Green

# ==================================================================
# 2) EXPORT LABEL POLICIES (Settings as TEXT -> JSON-safe)
# ==================================================================
Write-Host "Exporting label policies..." -ForegroundColor Yellow
$policiesOut = foreach ($p in (Get-LabelPolicy)) {
    [ordered]@{
        Name=$p.Name; Guid="$($p.Guid)"; Comment=$p.Comment; Labels=@($p.Labels)
        SettingsText=($p.Settings | Out-String).Trim(); AdvancedSettingsText=($p.AdvancedSettings | Out-String).Trim()
        ExchangeLocation=@($p.ExchangeLocation); SharePointLocation=@($p.SharePointLocation)
        OneDriveLocation=@($p.OneDriveLocation); ModernGroupLocation=@($p.ModernGroupLocation)
        Mode="$($p.Mode)"; Enabled=[bool]$p.Enabled
    }
}
$policiesOut | ConvertTo-Json -Depth 20 | Out-File "$OutFolder\label-policies.json" -Encoding UTF8
Write-Host ("Exported {0} label policies" -f @($policiesOut).Count) -ForegroundColor Green

# ==================================================================
# 3) AUDIT CSVs
# ==================================================================
$labelsOut | ForEach-Object {
    [pscustomobject]@{
        DisplayName=$_.DisplayName; Encryption=$_.EncryptionEnabled; RightsCount=@($_.EncryptionRightsDefinitions).Count
        Header=$_.HeaderEnabled; Footer=$_.FooterEnabled; Watermark=$_.WatermarkEnabled
        DynamicWatermark=$_.DynamicWatermarkEnabled; DynWmDisplay=$_.DynamicWatermarkDisplay
        AutoLabeling=$_.AutoLabelingEnabled; AutoApplyType=$_.AutoApplyType
    }
} | Export-Csv "$OutFolder\labels-summary.csv" -NoTypeInformation -Encoding UTF8

$rightsRows = foreach ($l in $labelsOut) { foreach ($r in $l.EncryptionRightsDefinitions) { [pscustomobject]@{ Label=$l.DisplayName; Identity=$r.Identity; Rights=$r.Rights } } }
$rightsRows | Export-Csv "$OutFolder\labels-rights.csv" -NoTypeInformation -Encoding UTF8

Write-Host "`nExport complete. Files in $OutFolder :" -ForegroundColor Cyan
Get-ChildItem $OutFolder | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "labels-summary.csv now includes DynamicWatermark + AutoLabeling columns." -ForegroundColor Yellow

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
