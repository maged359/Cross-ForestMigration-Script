<#
====================================================================
 export.ps1 : FULL EXPORT OF SENSITIVITY LABELS + POLICIES
====================================================================
 Captures EVERYTHING needed to recreate labels in Tenant B:
   - Encryption / access rights (rightsdefinitions, offline, expiry,
     DNF, encrypt-only, protection type)
   - CONTENT MARKING header/footer (text, font, size, color, align, margin)
   - STATIC WATERMARK (text, font, size, color, layout)
   - DYNAMIC WATERMARK (enabled + custom display string)   <-- NEW

 NOTE ON DYNAMIC WATERMARKING:
   It requires the label to have ENCRYPTION with ADMIN-DEFINED
   permissions. It cannot be applied to unencrypted or user-defined
   permission labels. Import applies it only after encryption is set.

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
        # dynamic watermark
        DynWmEnabled=$false; DynWmDisplay=$null
    }
    if (-not $label.LabelActions) { return $info }

    foreach ($actionRaw in $label.LabelActions) {
        $action = $actionRaw
        if ($actionRaw -is [string]) { try { $action = $actionRaw | ConvertFrom-Json } catch { continue } }
        $type    = "$($action.Type)".ToLower()
        $subType = "$($action.SubType)".ToLower()
        $st      = $action.Settings
        $disabled = (Get-SetVal $st "disabled")
        $isOn = -not ($disabled -and $disabled.ToLower() -eq "true")

        switch ($type) {
            "encrypt" {
                $info.EncEnabled        = $isOn
                $info.EncProtectionType = Get-SetVal $st "protectiontype"
                $info.EncOfflineDays    = Get-SetVal $st "offlineaccessdays"
                $info.EncExpiry         = Get-SetVal $st "contentexpiredondateindaysornever"
                $dnf = Get-SetVal $st "donotforward"; if ($dnf) { $info.EncDoNotForward = ($dnf.ToLower() -eq "true") }
                $eo  = Get-SetVal $st "encryptonly";  if ($eo)  { $info.EncEncryptOnly  = ($eo.ToLower()  -eq "true") }
                $rd = Get-SetVal $st "rightsdefinitions"
                if ($rd) { try { foreach ($r in ($rd | ConvertFrom-Json)) { $info.EncRights += [ordered]@{ Identity=$r.Identity; Rights=$r.Rights } } } catch {} }
                # dynamic watermark can live inside the encrypt action
                $dwe = Get-SetVal $st "dynamicwatermarkingenabled"; if ($dwe) { $info.DynWmEnabled = ($dwe.ToLower() -eq "true") }
                $dwd = Get-SetVal $st "dynamicwatermarkdisplay";    if ($dwd) { $info.DynWmDisplay = $dwd }
            }
            "applycontentmarking" {
                if ($subType -eq "header") {
                    $info.HdrEnabled=$isOn
                    $info.HdrText=Get-SetVal $st "text"; $info.HdrFontName=Get-SetVal $st "fontname"
                    $info.HdrFontSize=Get-SetVal $st "fontsize"; $info.HdrFontColor=Get-SetVal $st "fontcolor"
                    $info.HdrAlign=Get-SetVal $st "alignment"; $info.HdrMargin=Get-SetVal $st "margin"
                }
                elseif ($subType -eq "footer") {
                    $info.FtrEnabled=$isOn
                    $info.FtrText=Get-SetVal $st "text"; $info.FtrFontName=Get-SetVal $st "fontname"
                    $info.FtrFontSize=Get-SetVal $st "fontsize"; $info.FtrFontColor=Get-SetVal $st "fontcolor"
                    $info.FtrAlign=Get-SetVal $st "alignment"; $info.FtrMargin=Get-SetVal $st "margin"
                }
            }
            "applywatermarking" {
                $info.WmEnabled=$isOn
                $info.WmText=Get-SetVal $st "text"; $info.WmFontName=Get-SetVal $st "fontname"
                $info.WmFontSize=Get-SetVal $st "fontsize"; $info.WmFontColor=Get-SetVal $st "fontcolor"
                $info.WmLayout=Get-SetVal $st "layout"
                # some tenants surface dynamic watermark under the watermark action
                $dwe = Get-SetVal $st "dynamicwatermarkingenabled"; if ($dwe) { $info.DynWmEnabled = ($dwe.ToLower() -eq "true") }
                $dwd = Get-SetVal $st "dynamicwatermarkdisplay";    if ($dwd) { $info.DynWmDisplay = $dwd }
            }
        }
    }

    # Fallbacks: top-level properties if present
    if (-not $info.DynWmEnabled -and $label.PSObject.Properties.Name -contains "ApplyDynamicWatermarkingEnabled") {
        if ($label.ApplyDynamicWatermarkingEnabled) { $info.DynWmEnabled = $true }
    }
    if (-not $info.DynWmDisplay -and $label.PSObject.Properties.Name -contains "DynamicWatermarkDisplay") {
        if ($label.DynamicWatermarkDisplay) { $info.DynWmDisplay = $label.DynamicWatermarkDisplay }
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

        # ---- DYNAMIC WATERMARK ----
        DynamicWatermarkEnabled=$a.DynWmEnabled
        DynamicWatermarkDisplay=$a.DynWmDisplay
    }
}

$labelsOut | ConvertTo-Json -Depth 20 | Out-File "$OutFolder\labels.json" -Encoding UTF8
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
    }
} | Export-Csv "$OutFolder\labels-summary.csv" -NoTypeInformation -Encoding UTF8

$rightsRows = foreach ($l in $labelsOut) { foreach ($r in $l.EncryptionRightsDefinitions) { [pscustomobject]@{ Label=$l.DisplayName; Identity=$r.Identity; Rights=$r.Rights } } }
$rightsRows | Export-Csv "$OutFolder\labels-rights.csv" -NoTypeInformation -Encoding UTF8

Write-Host "`nExport complete. Files in $OutFolder :" -ForegroundColor Cyan
Get-ChildItem $OutFolder | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "labels-summary.csv now includes DynamicWatermark columns." -ForegroundColor Yellow

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
