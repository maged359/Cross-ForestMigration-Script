Install-Module -Name Microsoft.Online.SharePoint.PowerShell

Connect-SPOService -Url https://m365x18449975-admin.sharepoint.com 

$sites = Get-SPOSite -Limit All
$userInfoArray = @()
foreach ($site in $sites) {
    $users = Get-SPOUser -Site $site.Url
    foreach ($user in $users) {
        $userInfo = [PSCustomObject]@{
            'Site Url' = $site.Url
            'Login Name' = $user.LoginName
            'Display Name' = $user.DisplayName
            'Email' = $user.Email
        }
        $userInfoArray += $userInfo
    }
}
$userInfoArray | Export-Csv -Path "C:\package\spo.csv" -NoTypeInformation
Disconnect-SPOService
