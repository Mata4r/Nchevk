# nchevk.ps1 - Ping-sweep a subnet on Windows.
# Shows reachable hosts, hosts that exist (seen in the ARP table) but do not
# answer ping, and checks whether the default gateway is reachable.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\nchevk.ps1
#   Enter the subnet when asked; everything else is automatic.
# Works on Windows PowerShell 5.1 and PowerShell 7+. No admin rights needed.

$ErrorActionPreference = 'Stop'

function ConvertTo-UInt([string]$ip) {
    $b = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($b)
    [uint64][BitConverter]::ToUInt32($b, 0)
}

function ConvertTo-IPString([uint64]$n) {
    $b = [BitConverter]::GetBytes([uint32]$n)
    [Array]::Reverse($b)
    (New-Object System.Net.IPAddress(, $b)).ToString()
}

# ####### get subnet #######
$parsed = $null
while ($true) {
    $Subnet = (Read-Host "Enter subnet in CIDR notation (e.g. 192.168.1.0/24)").Trim()
    if ($Subnet -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$' -or
        -not [System.Net.IPAddress]::TryParse(($Subnet -split '/')[0], [ref]$parsed)) {
        Write-Host "Invalid subnet. Use CIDR like 192.168.1.0/24" -ForegroundColor Red
        continue
    }
    $prefix = [int]($Subnet -split '/')[1]
    if ($prefix -lt 16 -or $prefix -gt 30) {
        Write-Host "Prefix must be between /16 and /30." -ForegroundColor Red
        continue
    }
    break
}
$netAddr = ($Subnet -split '/')[0]

$all32   = [uint64]4294967295
$mask    = ($all32 -shl (32 - $prefix)) -band $all32
$netInt  = (ConvertTo-UInt $netAddr) -band $mask
$bcast   = $netInt -bor ($all32 -bxor $mask)
$first   = $netInt + 1
$last    = $bcast - 1
$total   = $last - $first + 1

Write-Host "Scanning $(ConvertTo-IPString $netInt)/$prefix ($total addresses)..." -ForegroundColor Cyan

# ####### ping sweep (async, in batches) #######
$reachable = New-Object System.Collections.Generic.HashSet[string]
$batchSize = 256

for ([uint64]$start = $first; $start -le $last; $start += $batchSize) {
    $end = [Math]::Min([uint64]($start + $batchSize - 1), $last)
    $jobs = @()
    for ([uint64]$i = $start; $i -le $end; $i++) {
        $ip   = ConvertTo-IPString $i
        $ping = New-Object System.Net.NetworkInformation.Ping
        $jobs += [pscustomobject]@{ IP = $ip; Ping = $ping; Task = $ping.SendPingAsync($ip, 1000) }
    }
    try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]($jobs.Task)) } catch { }
    foreach ($j in $jobs) {
        try {
            if ($j.Task.Result.Status -eq 'Success') { [void]$reachable.Add($j.IP) }
        } catch { }
        $j.Ping.Dispose()
    }
}

# ####### neighbor (ARP) table #######
$neighbors = @{}
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.State -notin 'Unreachable', 'Incomplete' -and
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)'
    } |
    ForEach-Object {
        $v = ConvertTo-UInt $_.IPAddress
        if ($v -ge $first -and $v -le $last) { $neighbors[$_.IPAddress] = $_.LinkLayerAddress }
    }

$reachableSorted = $reachable | Sort-Object { [version]$_ }
$unreachableKnown = $neighbors.Keys | Where-Object { -not $reachable.Contains($_) } |
    Sort-Object { [version]$_ }

# ####### results #######
Write-Host ""
Write-Host "=== Reachable hosts ($($reachable.Count)) ===" -ForegroundColor White
if ($reachable.Count) {
    foreach ($ip in $reachableSorted) {
        $mac = if ($neighbors.ContainsKey($ip)) { $neighbors[$ip] } else { "" }
        Write-Host ("  {0,-16} UP   {1}" -f $ip, $mac) -ForegroundColor Green
    }
} else { Write-Host "  none" }

Write-Host ""
Write-Host "=== Exist on the network but NOT reachable by ping ($(@($unreachableKnown).Count)) ===" -ForegroundColor White
if (@($unreachableKnown).Count) {
    foreach ($ip in $unreachableKnown) {
        Write-Host ("  {0,-16} NO PING REPLY   {1}" -f $ip, $neighbors[$ip]) -ForegroundColor Yellow
    }
    Write-Host "  (Seen in the ARP table, so a device has that IP, but it blocks ICMP or went offline.)"
} else { Write-Host "  none" }

# ####### gateway check #######
Write-Host ""
Write-Host "=== Gateway check ===" -ForegroundColor White

$gw = $null
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric | Select-Object -First 1
if ($route) { $gw = $route.NextHop }

if (-not $gw) {
    Write-Host "  No default gateway found on this PC (not connected to a network?)." -ForegroundColor Yellow
} else {
    $gv = ConvertTo-UInt $gw
    if ($gv -lt $netInt -or $gv -gt $bcast) {
        Write-Host "  Note: gateway $gw is outside the scanned subnet."
    }
    if (Test-Connection -ComputerName $gw -Count 3 -Quiet) {
        Write-Host "  Gateway ${gw}: REACHABLE" -ForegroundColor Green
    } else {
        Write-Host "  Gateway ${gw}: NOT REACHABLE" -ForegroundColor Red
        if (Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue |
            Where-Object { $_.State -notin 'Unreachable', 'Incomplete' }) {
            Write-Host "  (It is in the ARP table, so it exists but may be blocking ping.)"
        }
    }
}

# ####### summary #######
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor White
Write-Host "  Subnet scanned : $(ConvertTo-IPString $netInt)/$prefix"
Write-Host "  Addresses      : $total"
Write-Host "  Reachable      : $($reachable.Count)"
Write-Host "  Exist, no ping : $(@($unreachableKnown).Count)"
Write-Host "  No response    : $($total - $reachable.Count - @($unreachableKnown).Count)"
