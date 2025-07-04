# --- Configuration ---
$newDomain = "Target Domain"
$newOU = "Target-OU"  # Optional
$newDomainUsername = ""
$newDomainPassword = "" | ConvertTo-SecureString -AsPlainText -Force
$newDomainCred = New-Object System.Management.Automation.PSCredential ($newDomainUsername, $newDomainPassword)

# --- Step 1: Copy all user profiles to D:\NewUserBackup ---
try {
    $backupRoot = "D:\NewUserBackup"
    $foldersToBackup = @("Desktop", "Documents", "Downloads", "Favorites")

    # Get all user profiles under C:\Users (excluding system profiles)
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object {
        $_.Name -notin @("Public", "Default", "Default User", "All Users", "Administrator")
    }

    foreach ($profile in $userProfiles) {
        $username = $profile.Name
        $sourceProfilePath = $profile.FullName
        $destinationBase = Join-Path $backupRoot $username

        Write-Output "Backing up profile: $username"

        foreach ($folder in $foldersToBackup) {
            $sourceFolder = Join-Path $sourceProfilePath $folder
            $destinationFolder = Join-Path $destinationBase $folder

            if (Test-Path $sourceFolder) {
                Write-Output "Copying $sourceFolder to $destinationFolder..."
                New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
                robocopy $sourceFolder $destinationFolder /E /Z /R:2 /W:2 /NFL /NDL /NP
            } else {
                Write-Output "Folder $sourceFolder not found. Skipping."
            }
        }
    }
} catch {
    Write-Output "Error while copying profiles: $_"
}

# --- Step 2: Join the new domain ---
try {
    Write-Output "Joining domain $newDomain..."
    Add-Computer -DomainName $newDomain -OUPath $newOU -Credential $newDomainCred

    Write-Output "Domain join successful. Rebooting..."
    Restart-Computer -Force
} catch {
    Write-Output "Failed to join $newDomain $_"
}
