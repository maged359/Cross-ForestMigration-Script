# Get all adapters that have IPv4 DNS settings
$dnsAdapters = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {
    $_.ServerAddresses.Count -gt 0
}

if ($dnsAdapters.Count -eq 0) {
    Write-Output "No DNS server addresses found on any adapter."
    exit 1
}

foreach ($adapter in $dnsAdapters) {
    Write-Output "Adapter: $($adapter.InterfaceAlias)"
    
    $i = 1
    foreach ($dns in $adapter.ServerAddresses) {
        if ($i -eq 1) {
            Write-Output "  Primary DNS: $dns"
        } else {
            Write-Output "  Secondary DNS $i $dns"
        }
        $i++
    }
}

exit 0