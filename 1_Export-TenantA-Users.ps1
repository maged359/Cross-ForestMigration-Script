<#
====================================================================
 SCRIPT 1 : EXPORT USERS FROM TENANT A (SOURCE)
====================================================================
 Purpose : Export all users + attributes from Tenant A to a CSV file.
 Module  : Microsoft.Graph  (Microsoft Graph PowerShell SDK)
 Auth    : Sign in with an admin of TENANT A (source).

 One-time setup (run once on your machine):
     Install-Module Microsoft.Graph -Scope CurrentUser -Force
====================================================================
#>

# ---- CONFIG -------------------------------------------------------
$ExportPath = ".\TenantA_Users_Export.csv"     # output CSV
# -------------------------------------------------------------------

# 1) Connect to TENANT A (source) - read directory
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All"

Write-Host "Connected to:" (Get-MgContext).TenantId -ForegroundColor Cyan
Write-Host "Exporting users..." -ForegroundColor Yellow

# 2) Attributes to export (add/remove as needed)
$props = @(
    "Id","DisplayName","UserPrincipalName","MailNickname","GivenName","Surname",
    "JobTitle","Department","CompanyName","OfficeLocation","StreetAddress","City",
    "State","PostalCode","Country","UsageLocation","BusinessPhones","MobilePhone",
    "FaxNumber","Mail","OtherMails","ProxyAddresses","PreferredLanguage",
    "EmployeeId","EmployeeType","AccountEnabled","AgeGroup"
)

# 3) Pull all users (handles paging automatically with -All)
$users = Get-MgUser -All -Property $props |
    Select-Object `
        DisplayName, UserPrincipalName, MailNickname, GivenName, Surname,
        JobTitle, Department, CompanyName, OfficeLocation, StreetAddress, City,
        State, PostalCode, Country, UsageLocation,
        @{N="BusinessPhones";E={ ($_.BusinessPhones -join ";") }},
        MobilePhone, FaxNumber, Mail,
        @{N="OtherMails";E={ ($_.OtherMails -join ";") }},
        @{N="ProxyAddresses";E={ ($_.ProxyAddresses -join ";") }},
        PreferredLanguage, EmployeeId, EmployeeType, AccountEnabled

# 4) Export to CSV
$users | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

Write-Host ("Exported {0} users to {1}" -f $users.Count, (Resolve-Path $ExportPath)) -ForegroundColor Green

Disconnect-MgGraph | Out-Null
