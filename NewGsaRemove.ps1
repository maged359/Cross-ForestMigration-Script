$services = @(
    "GlobalSecureAccessAutoUpgradeService",
    "GlobalSecureAccessPolicyRetrieverService",
    "GlobalSecureAccessTunnelingService",
    "Global Secure Access Management Service"
)

foreach ($svc in $services) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    } catch {}
}

# Define uninstall registry paths
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# Try to locate GSA in registry
$gsaApp = $null
foreach ($key in $uninstallKeys) {
    $gsaApp = Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*Global Secure Access*"
    }
    if ($gsaApp) { break }
}

if ($gsaApp) {
    $displayName = $gsaApp.DisplayName
    $uninstallString = $gsaApp.UninstallString
    $productCode = $gsaApp.PSChildName  # For MSI products

    Write-Output "Found: $displayName"

    if ($uninstallString -like "*msiexec*") {
        # Uninstall MSI
        Write-Output "Uninstalling via msiexec..."
        $cmd = "msiexec.exe /x $productCode /qn /norestart"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -Wait -WindowStyle Hidden
    }
    elseif ($uninstallString) {
        Write-Output "Uninstalling via uninstall string..."
        # Handle quoted strings
        if ($uninstallString.StartsWith('"')) {
            $exePath = $uninstallString -replace '^"([^"]+)"\s*(.*)$', '$1'
            $arguments = $uninstallString -replace '^"[^"]+"\s*', ''
        } else {
            $parts = $uninstallString -split "\s+", 2
            $exePath = $parts[0]
            $arguments = if ($parts.Count -gt 1) { $parts[1] } else { "" }
        }
        Start-Process -FilePath $exePath -ArgumentList "$arguments /quiet" -Wait -WindowStyle Hidden
    }
}

# Fallback to winget uninstall if present
try {
    winget uninstall --name "Global Secure Access" --silent --accept-package-agreements --accept-source-agreements
} catch {}

# Remove folders
$folders = @(
    "C:\Program Files\Microsoft\Global Secure Access",
    "C:\ProgramData\Microsoft\Global Secure Access"
)
foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Remove from registry if still present
foreach ($key in $uninstallKeys) {
    $entries = Get-ChildItem $key -ErrorAction SilentlyContinue
    foreach ($entry in $entries) {
        try {
            $props = Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like "*Global Secure Access*") {
                Remove-Item -Path $entry.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Output "Removed leftover registry entry: $($props.DisplayName)"
            }
        } catch {}
    }
}

Write-Output "✅ Global Secure Access client removal complete."
