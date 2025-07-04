# Define the list of required ports for domain controller communication
$requiredPorts = @(53, 88, 135, 389, 445, 636, 3268, 3269)

# Specify the domain controller hostname or IP
$domainController = "XXX"

# Initialize an array to store blocked ports
$blockedPorts = @()

# Loop through each port and test connectivity
foreach ($port in $requiredPorts) {
    $connection = Test-NetConnection -ComputerName $domainController -Port $port
    if (-not $connection.TcpTestSucceeded) {
        Write-Host "Port $port is blocked on $domainController"
        $blockedPorts += $port
    } else {
        Write-Host "Port $port is open on $domainController"
    }
}

# Output the list of blocked ports, if any
if ($blockedPorts.Count -gt 0) {
    Write-Host "The following ports are blocked on $domainController $($blockedPorts -join ', ')"
} else {
    Write-Host "All required ports are open on $domainController."
}

# Exit code for Intune detection
if ($blockedPorts.Count -gt 0) {
    exit 1 # Detection fails if any ports are blocked
} else {
    exit 0 # Detection succeeds if all ports are open
}
