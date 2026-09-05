<#
====================================================================
 SCRIPT 2 : CREATE USERS IN TENANT B (DESTINATION)
====================================================================
 Purpose : Read the CSV exported from Tenant A and create the users
           in Tenant B with a CUSTOM password.
 Module  : Microsoft.Graph  (Microsoft Graph PowerShell SDK)
 Auth    : Sign in with an admin of TENANT B (destination).

 IMPORTANT - UPN / domain:
   Tenant A UPNs use tenantA domains that DO NOT exist in Tenant B.
   You MUST re-home each user onto a domain verified in Tenant B.
   This script rewrites the UPN domain to $TargetDomain below.
====================================================================
#>

# ---- CONFIG -------------------------------------------------------
$ImportPath    = ".\TenantA_Users_Export.csv"          # CSV from Script 1
$TargetDomain  = "m365x18449975.onmicrosoft.com"       # a VERIFIED domain in Tenant B
$CustomPassword= "P@ssw0rd-Change2026!"                # custom password for all users
$ForceChange   = $true    # $true = user must change password at first sign-in
$LogPath       = ".\TenantB_Import_Log.csv"
# -------------------------------------------------------------------

# 1) Connect to TENANT B (destination) - write users
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All"

Write-Host "Connected to:" (Get-MgContext).TenantId -ForegroundColor Cyan

# 2) Load CSV
$rows = Import-Csv -Path $ImportPath
Write-Host ("Loaded {0} users from CSV" -f $rows.Count) -ForegroundColor Yellow

$log = @()

foreach ($u in $rows) {

    # Rebuild the UPN onto the destination's verified domain
    $prefix = ($u.UserPrincipalName -split "@")[0]
    $newUpn = "$prefix@$TargetDomain"

    # MailNickname is required; derive if missing
    $nickname = if ([string]::IsNullOrWhiteSpace($u.MailNickname)) { $prefix } else { $u.MailNickname }

    $passwordProfile = @{
        Password                      = $CustomPassword
        ForceChangePasswordNextSignIn = [bool]$ForceChange
    }

    # Build the parameter set (only include non-empty fields)
    $params = @{
        AccountEnabled    = $true
        DisplayName       = $u.DisplayName
        UserPrincipalName = $newUpn
        MailNickname      = $nickname
        PasswordProfile   = $passwordProfile
    }

    if ($u.GivenName)       { $params.GivenName       = $u.GivenName }
    if ($u.Surname)         { $params.Surname         = $u.Surname }
    if ($u.JobTitle)        { $params.JobTitle        = $u.JobTitle }
    if ($u.Department)      { $params.Department      = $u.Department }
    if ($u.CompanyName)     { $params.CompanyName     = $u.CompanyName }
    if ($u.OfficeLocation)  { $params.OfficeLocation  = $u.OfficeLocation }
    if ($u.StreetAddress)   { $params.StreetAddress   = $u.StreetAddress }
    if ($u.City)            { $params.City            = $u.City }
    if ($u.State)           { $params.State           = $u.State }
    if ($u.PostalCode)      { $params.PostalCode      = $u.PostalCode }
    if ($u.Country)         { $params.Country         = $u.Country }
    if ($u.UsageLocation)   { $params.UsageLocation   = $u.UsageLocation }
    if ($u.MobilePhone)     { $params.MobilePhone     = $u.MobilePhone }
    if ($u.PreferredLanguage){ $params.PreferredLanguage = $u.PreferredLanguage }
    if ($u.EmployeeId)      { $params.EmployeeId      = $u.EmployeeId }
    if ($u.EmployeeType)    { $params.EmployeeType    = $u.EmployeeType }
    if ($u.BusinessPhones)  { $params.BusinessPhones  = @($u.BusinessPhones -split ";") }

    try {
        $created = New-MgUser -BodyParameter $params -ErrorAction Stop
        Write-Host ("CREATED : {0}" -f $newUpn) -ForegroundColor Green
        $log += [pscustomobject]@{ UPN=$newUpn; Status="Created"; Id=$created.Id; Error="" }
    }
    catch {
        Write-Host ("FAILED  : {0}  -->  {1}" -f $newUpn, $_.Exception.Message) -ForegroundColor Red
        $log += [pscustomobject]@{ UPN=$newUpn; Status="Failed"; Id=""; Error=$_.Exception.Message }
    }
}

# 3) Write result log
$log | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
Write-Host ("Done. Log written to {0}" -f (Resolve-Path $LogPath)) -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null
