<#
====================================================================
 export.ps1 : ENHANCED EXPORT OF SENSITIVITY LABELS + POLICIES
====================================================================
 Exports from TENANT A (source), capturing EVERYTHING needed to
 recreate labels in Tenant B INCLUDING encryption/access rights.

 KEY ENHANCEMENTS vs. earlier versions:
   - Parses LabelActions and extracts encryption settings into a
     CLEAN, dedicated structure (rights definitions, offline days,
     expiry, DNF, encrypt-only, protection type) -> no reliance on
     raw blobs that break ConvertFrom-Json.
   - Serializes Settings/AdvancedSettings as TEXT to avoid the
     PowerShell 5.1 'value'/'Value' duplicate-key JSON error.
   - Fixes the -IncludeDetailedLabelActions switch (no $true value).

 Module : ExchangeOnlineManagement (Security & Compliance PowerShell)
 Auth   : Compliance Administrator of TENANT A (source).

 RUN IN POWERSHELL 7 (pwsh) for cleanest results.

 One-time setup:
     Install-Module ExchangeOnlineManagement -MinimumVersion 3.4.0 -Scope CurrentUser

 Usage:
     pwsh
     .\export.ps1
====================================================================
#>

# ---- CONFIG -------------------------------------------------------
$AdminUPN  = "admin@tenantA.onmicrosoft.com"   # Tenant A compliance admin
$OutFolder = ".\LabelExport"
# -------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $OutFolder | Out-Null

Import-Module ExchangeOnlineManagement
Connect-IPPSSession -UserPrincipalName $AdminUPN
Write-Host "Connected to Tenant A Security & Compliance." -ForegroundColor Cyan

# ------- helper: extract clean encryption info from LabelActions -------
function Get-EncryptionInfo($label) {
    $info = [ordered]@{
        HasEncryption     = $false
        ProtectionType    = $null
        OfflineDays       = $null
        ExpiryDaysOrNever = $null
        DoNotForward      = $false
        EncryptOnly       = $false
        RightsDefinitions = @()    # array of @{ Identity=..; Rights=.. }
    }
    if (-not $label.LabelActions) { return $info }

    foreach ($actionRaw in $label.LabelActions) {
        $action = $actionRaw
        if ($actionRaw -is [string]) {
            try { $action = $actionRaw | ConvertFrom-Json } catch { continue }
        }
        if ($action.Type -ne "encrypt") { continue }
        $info.HasEncryption = $true

        foreach ($s in $action.Settings) {
            $key = "$($s.Key)".ToLower()
            switch ($key) {
                "rightsdefinitions" {
                    try {
                        $rd = $s.Value | ConvertFrom-Json
                        foreach ($r in $rd) {
                            $info.RightsDefinitions += [ordered]@{
                                Identity = $r.Identity
                                Rights   = $r.Rights
                            }
                        }
                    } catch {}
                }
                "protectiontype"                    { $info.ProtectionType    = $s.Value }
                "offlineaccessdays"                 { $info.OfflineDays       = $s.Value }
                "contentexpiredondateindaysornever" { $info.ExpiryDaysOrNever = $s.Value }
                "donotforward"                      { $info.DoNotForward      = ("$($s.Value)".ToLower() -eq "true") }
                "encryptonly"                       { $info.EncryptOnly       = ("$($s.Value)".ToLower() -eq "true") }
            }
        }
    }
    return $info
}

# ==================================================================
# 1) EXPORT LABELS (with clean encryption structure)
# ==================================================================
Write-Host "Exporting sensitivity labels..." -ForegroundColor Yellow
$rawLabels = @(Get-Label -IncludeDetailedLabelActions)

$labelsOut = foreach ($l in $rawLabels) {
    $enc = Get-EncryptionInfo $l
    [ordered]@{
        DisplayName                      = $l.DisplayName
        Name                             = $l.Name
        Guid                             = "$($l.Guid)"
        ParentId                         = "$($l.ParentId)"
        Priority                         = $l.Priority
        Tooltip                          = $l.Tooltip
        Comment                          = $l.Comment
        IsParent                         = [bool]$l.IsParent
        ApplyContentMarkingHeaderEnabled = [bool]$l.ApplyContentMarkingHeaderEnabled
        ApplyContentMarkingHeaderText    = $l.ApplyContentMarkingHeaderText
        ApplyContentMarkingFooterEnabled = [bool]$l.ApplyContentMarkingFooterEnabled
        ApplyContentMarkingFooterText    = $l.ApplyContentMarkingFooterText
        ApplyWaterMarkingEnabled         = [bool]$l.ApplyWaterMarkingEnabled
        ApplyWaterMarkingText            = $l.ApplyWaterMarkingText
        # ---- clean encryption block ----
        EncryptionEnabled                = $enc.HasEncryption
        EncryptionProtectionType         = $enc.ProtectionType
        EncryptionOfflineAccessDays      = $enc.OfflineDays
        EncryptionContentExpiry          = $enc.ExpiryDaysOrNever
        EncryptionDoNotForward           = $enc.DoNotForward
        EncryptionEncryptOnly            = $enc.EncryptOnly
        EncryptionRightsDefinitions      = $enc.RightsDefinitions
    }
}

$labelsOut | ConvertTo-Json -Depth 20 | Out-File "$OutFolder\labels.json" -Encoding UTF8
Write-Host ("Exported {0} labels" -f @($labelsOut).Count) -ForegroundColor Green

# ==================================================================
# 2) EXPORT LABEL POLICIES (Settings serialized as TEXT -> JSON-safe)
# ==================================================================
Write-Host "Exporting label policies..." -ForegroundColor Yellow
$policiesOut = foreach ($p in (Get-LabelPolicy)) {
    [ordered]@{
        Name                       = $p.Name
        Guid                       = "$($p.Guid)"
        Comment                    = $p.Comment
        Labels                     = @($p.Labels)
        SettingsText               = ($p.Settings        | Out-String).Trim()
        AdvancedSettingsText       = ($p.AdvancedSettings | Out-String).Trim()
        ExchangeLocation           = @($p.ExchangeLocation)
        SharePointLocation         = @($p.SharePointLocation)
        OneDriveLocation           = @($p.OneDriveLocation)
        ModernGroupLocation        = @($p.ModernGroupLocation)
        Mode                       = "$($p.Mode)"
        Enabled                    = [bool]$p.Enabled
    }
}

$policiesOut | ConvertTo-Json -Depth 20 | Out-File "$OutFolder\label-policies.json" -Encoding UTF8
Write-Host ("Exported {0} label policies" -f @($policiesOut).Count) -ForegroundColor Green

# ==================================================================
# 3) READABLE AUDIT CSVs
# ==================================================================
$labelsOut | ForEach-Object {
    [pscustomobject]@{
        DisplayName       = $_.DisplayName
        Priority          = $_.Priority
        IsParent          = $_.IsParent
        Encryption        = $_.EncryptionEnabled
        RightsCount       = @($_.EncryptionRightsDefinitions).Count
        Watermark         = $_.ApplyWaterMarkingEnabled
    }
} | Export-Csv "$OutFolder\labels-summary.csv" -NoTypeInformation -Encoding UTF8

# rights detail CSV (who gets what) for your review
$rightsRows = foreach ($l in $labelsOut) {
    foreach ($r in $l.EncryptionRightsDefinitions) {
        [pscustomobject]@{ Label=$l.DisplayName; Identity=$r.Identity; Rights=$r.Rights }
    }
}
$rightsRows | Export-Csv "$OutFolder\labels-rights.csv" -NoTypeInformation -Encoding UTF8

Write-Host "`nExport complete. Files in $OutFolder :" -ForegroundColor Cyan
Get-ChildItem $OutFolder | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "`nReview labels-rights.csv to see the access permissions captured per label." -ForegroundColor Yellow

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
