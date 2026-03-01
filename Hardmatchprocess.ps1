# =============================
# SECTION 1: Credentials & Hostnames
# =============================

# Source (gpo.local)
$srcCred  = New-Object PSCredential 'gpo\megz', (ConvertTo-SecureString 'password' -AsPlainText -Force)
$srcDC    = 'dc.gpo.local'

# AD Connect (same DC)
$adSyncCred = $srcCred
$adConnect  = 'dc.gpo.local'

# Target (forestb.local)
$targetCred = New-Object PSCredential 'forestb\admin', (ConvertTo-SecureString 'password' -AsPlainText -Force)
$targetDC   = 'dc02.forestb.local'


# User & Device Distinguished Names
$userCN = 'CN=crossforest'
$deviceCN = 'CN=cross-forest'
$dispname = 'crossforest'

# OU Paths
$srcOldOU     = 'OU=M365,DC=gpo,DC=local'
$srcNewOU     = 'OU=Target,DC=gpo,DC=local'
$targetOldOU  = 'OU=unsync,DC=forestb,DC=local'
$targetNewOU  = 'OU=sync,DC=forestb,DC=local'

# =============================
# SECTION 2: Move in gpo.local (Source Domain)
# =============================
Invoke-Command -ComputerName $srcDC -Credential $srcCred -ScriptBlock {
    param($userCN, $deviceCN, $srcOldOU, $srcNewOU)
    Move-ADObject -Identity "$userCN,$srcOldOU" -TargetPath $srcNewOU
    Move-ADObject -Identity "$deviceCN,$srcOldOU" -TargetPath $srcNewOU
    Write-Host "✅ Moved user and device to $srcNewOU in gpo.local"
} -ArgumentList $userCN, $deviceCN, $srcOldOU, $srcNewOU

# =============================
# SECTION 3: Trigger First Delta Sync (AD Connect)
# =============================
Invoke-Command -ComputerName $adConnect -Credential $adSyncCred -ScriptBlock {
    Start-ADSyncSyncCycle -PolicyType Delta
    Write-Host "✅ Delta Sync #1 triggered from AD Connect"
}
Start-Sleep -Seconds 200

# =============================
# SECTION 4: Restore User in Entra + Clear ImmutableId
# =============================

# Configuration
$ClientId = "3343b3c0-ba38-4d6e-b4ce-c2487e5ee550"
$TenantId = "6948e8cd-3b86-423e-8a9f-19f947e9c172"
$ClientSecret = "e6E8Q~ig3CQWfqYcZOHicPRFftHqUgGbAn91ual2"

# Convert the client secret to a secure string
$ClientSecretPass = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force

# Create a credential object using the client ID and secure string
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $ClientSecretPass

# Connect to Microsoft Graph with Client Secret
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $ClientSecretCredential


# Get deleted user by displayName
$DeletedUser = Get-MgDirectoryDeletedItemasUser -Filter "displayName eq '$dispname'"

# Restore the user
Restore-MgDirectoryDeletedItem -DirectoryObjectId $DeletedUser.Id

# Define UPN
$upn = "crossforest@FTC89.onmicrosoft.com"

# Get the Object ID from Microsoft Graph
$user = Get-MgUser -UserId $upn | Select-Object Id, UserPrincipalName
$objectId = $user.Id

# Clear onPremisesImmutableId using PATCH request
Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$objectId" -Body @{ onPremisesImmutableId = $null }

Write-Host "✅ Cleared onPremisesImmutableId for $($user.UserPrincipalName)"

Start-Sleep -Seconds 120

# =============================
# SECTION 5: Move in forestb.local (Target Domain)
# =============================
Invoke-Command -ComputerName $targetDC -Credential $targetCred -ScriptBlock {
    param($userCN, $deviceCN, $targetOldOU, $targetNewOU)
    Move-ADObject -Identity "$userCN,$targetOldOU" -TargetPath $targetNewOU
    Move-ADObject -Identity "$deviceCN,$targetOldOU" -TargetPath $targetNewOU
    Write-Host "✅ Moved user and device to $targetNewOU in forestb.local"
} -ArgumentList $userCN, $deviceCN, $targetOldOU, $targetNewOU

# =============================
# SECTION 6: Final Delta Sync (Post-Restore)
# =============================
Invoke-Command -ComputerName $adConnect -Credential $adSyncCred -ScriptBlock {
    Start-ADSyncSyncCycle -PolicyType Delta
    Write-Host "✅ Final Delta Sync triggered"
}

Stop-Transcript
