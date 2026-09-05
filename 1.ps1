<#
====================================================================
 SCRIPT 4 : EXPORT SECURITY GROUPS (+ MEMBERS) FROM TENANT A
====================================================================
 Purpose : Export all security groups and their members from Tenant A
           to two CSV files:
             - TenantA_Groups_Export.csv    (group definitions)
             - TenantA_GroupMembers.csv     (group -> member map)
 Module  : Microsoft.Graph
 Auth    : Sign in with an admin of TENANT A (source).

 Notes:
   - Exports SECURITY groups (mailEnabled=false, securityEnabled=true).
   - Skips dynamic groups for member export (membership is rule-based).
   - Members are recorded by their SOURCE UPN so Script 5 can re-map them
     to the destination domain.
====================================================================
#>

# ---- CONFIG -------------------------------------------------------
$GroupsPath  = ".\TenantA_Groups_Export.csv"
$MembersPath = ".\TenantA_GroupMembers.csv"
# -------------------------------------------------------------------

# 1) Connect to TENANT A
Connect-MgGraph -Scopes "Group.Read.All","GroupMember.Read.All","User.Read.All","Directory.Read.All"
Write-Host "Connected to:" (Get-MgContext).TenantId -ForegroundColor Cyan

# 2) Get all SECURITY groups (exclude M365/distribution/mail-enabled)
Write-Host "Retrieving security groups..." -ForegroundColor Yellow
$groups = Get-MgGroup -All -Property "Id,DisplayName,Description,MailNickname,SecurityEnabled,MailEnabled,GroupTypes,IsAssignableToRole" |
    Where-Object { $_.SecurityEnabled -eq $true -and $_.MailEnabled -eq $false }

Write-Host ("Found {0} security groups" -f $groups.Count) -ForegroundColor Green

$groupOut   = @()
$memberOut  = @()

foreach ($g in $groups) {

    $isDynamic = ($g.GroupTypes -contains "DynamicMembership")

    $groupOut += [pscustomobject]@{
        DisplayName        = $g.DisplayName
        Description        = $g.Description
        MailNickname       = $g.MailNickname
        IsAssignableToRole = $g.IsAssignableToRole
        IsDynamic          = $isDynamic
        GroupTypes         = ($g.GroupTypes -join ";")
    }

    # 3) Export members ONLY for assigned (non-dynamic) groups
    if (-not $isDynamic) {
        $members = Get-MgGroupMember -GroupId $g.Id -All
        foreach ($m in $members) {
            # resolve UPN for user members (skip nested groups/SPNs here)
            $upn = $m.AdditionalProperties["userPrincipalName"]
            $otype = $m.AdditionalProperties["@odata.type"]
            if ($upn) {
                $memberOut += [pscustomobject]@{
                    GroupDisplayName = $g.DisplayName
                    MemberUPN        = $upn
                    MemberType       = "User"
                }
            }
            elseif ($otype -like "*group*") {
                $memberOut += [pscustomobject]@{
                    GroupDisplayName = $g.DisplayName
                    MemberUPN        = $m.AdditionalProperties["displayName"]
                    MemberType       = "Group"   # nested group (add manually/second pass)
                }
            }
        }
    }
}

# 4) Export CSVs
$groupOut  | Export-Csv -Path $GroupsPath  -NoTypeInformation -Encoding UTF8
$memberOut | Export-Csv -Path $MembersPath -NoTypeInformation -Encoding UTF8

Write-Host ("Exported {0} groups to {1}" -f $groupOut.Count, (Resolve-Path $GroupsPath)) -ForegroundColor Green
Write-Host ("Exported {0} membership rows to {1}" -f $memberOut.Count, (Resolve-Path $MembersPath)) -ForegroundColor Green

Disconnect-MgGraph | Out-Null
