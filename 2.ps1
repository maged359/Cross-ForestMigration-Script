<#
====================================================================
 SCRIPT 5 : CREATE SECURITY GROUPS (+ MEMBERS) IN TENANT B
====================================================================
 Purpose : Recreate the security groups from Tenant A in Tenant B and
           re-add members, mapping each member to the destination UPN.
 Module  : Microsoft.Graph
 Auth    : Sign in with an admin of TENANT B (destination).

 Inputs  :
   - TenantA_Groups_Export.csv   (from Script 4)
   - TenantA_GroupMembers.csv    (from Script 4)

 UPN mapping:
   Source members are stored with their Tenant A UPN. The prefix is kept
   and re-homed onto $TargetDomain (same logic used when creating users
   in Script 2), so members resolve to the users you created in Tenant B.
====================================================================
#>

# ---- CONFIG -------------------------------------------------------
$GroupsPath   = ".\TenantA_Groups_Export.csv"
$MembersPath  = ".\TenantA_GroupMembers.csv"
$TargetDomain = "m365x18449975.onmicrosoft.com"   # verified domain in Tenant B
$GroupLog     = ".\TenantB_Groups_Log.csv"
$MemberLog    = ".\TenantB_GroupMembers_Log.csv"
# -------------------------------------------------------------------

# 1) Connect to TENANT B
Connect-MgGraph -Scopes "Group.ReadWrite.All","GroupMember.ReadWrite.All","User.Read.All","Directory.ReadWrite.All"
Write-Host "Connected to:" (Get-MgContext).TenantId -ForegroundColor Cyan

# 2) Load CSVs
$groups  = Import-Csv -Path $GroupsPath
$members = Import-Csv -Path $MembersPath
Write-Host ("Loaded {0} groups, {1} membership rows" -f $groups.Count, $members.Count) -ForegroundColor Yellow

$groupLog  = @()
$groupIdMap = @{}   # DisplayName -> new GroupId in Tenant B

# 3) Create the groups
foreach ($g in $groups) {

    # Skip dynamic groups here (membership is rule-based; recreate manually)
    if ($g.IsDynamic -eq "True") {
        Write-Host ("SKIP (dynamic): {0}" -f $g.DisplayName) -ForegroundColor DarkYellow
        $groupLog += [pscustomobject]@{ DisplayName=$g.DisplayName; Status="Skipped-Dynamic"; Id=""; Error="" }
        continue
    }

    $nick = if ([string]::IsNullOrWhiteSpace($g.MailNickname)) {
        ($g.DisplayName -replace '[^a-zA-Z0-9]','')
    } else { $g.MailNickname }

    $params = @{
        DisplayName     = $g.DisplayName
        Description     = $g.Description
        MailNickname    = $nick
        SecurityEnabled = $true
        MailEnabled     = $false
        GroupTypes      = @()               # assigned security group
    }
    if ($g.IsAssignableToRole -eq "True") { $params.IsAssignableToRole = $true }

    try {
        $created = New-MgGroup -BodyParameter $params -ErrorAction Stop
        $groupIdMap[$g.DisplayName] = $created.Id
        Write-Host ("CREATED group : {0}" -f $g.DisplayName) -ForegroundColor Green
        $groupLog += [pscustomobject]@{ DisplayName=$g.DisplayName; Status="Created"; Id=$created.Id; Error="" }
    }
    catch {
        Write-Host ("FAILED group  : {0}  -->  {1}" -f $g.DisplayName, $_.Exception.Message) -ForegroundColor Red
        $groupLog += [pscustomobject]@{ DisplayName=$g.DisplayName; Status="Failed"; Id=""; Error=$_.Exception.Message }
    }
}

$groupLog | Export-Csv -Path $GroupLog -NoTypeInformation -Encoding UTF8

# 4) Add members (user members only; nested groups handled separately)
$memberLog = @()
foreach ($m in $members) {

    if ($m.MemberType -ne "User") { continue }   # skip nested-group rows

    $groupId = $groupIdMap[$m.GroupDisplayName]
    if (-not $groupId) { continue }              # group wasn't created

    # Re-home member UPN to destination domain
    $prefix = ($m.MemberUPN -split "@")[0]
    $newUpn = "$prefix@$TargetDomain"

    try {
        $u = Get-MgUser -UserId $newUpn -Property Id -ErrorAction Stop
        New-MgGroupMember -GroupId $groupId -DirectoryObjectId $u.Id -ErrorAction Stop
        Write-Host ("  + {0}  ->  {1}" -f $newUpn, $m.GroupDisplayName) -ForegroundColor Green
        $memberLog += [pscustomobject]@{ Group=$m.GroupDisplayName; Member=$newUpn; Status="Added"; Error="" }
    }
    catch {
        Write-Host ("  ! {0}  ->  {1}  ({2})" -f $newUpn, $m.GroupDisplayName, $_.Exception.Message) -ForegroundColor Red
        $memberLog += [pscustomobject]@{ Group=$m.GroupDisplayName; Member=$newUpn; Status="Failed"; Error=$_.Exception.Message }
    }
}

$memberLog | Export-Csv -Path $MemberLog -NoTypeInformation -Encoding UTF8

Write-Host ("`nDone. Group log: {0}" -f (Resolve-Path $GroupLog)) -ForegroundColor Cyan
Write-Host ("Member log: {0}" -f (Resolve-Path $MemberLog)) -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null
