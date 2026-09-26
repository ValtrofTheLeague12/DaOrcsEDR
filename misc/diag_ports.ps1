# Identify the owners of the candidate API ports (5000 / 8080).
$ErrorActionPreference = 'Continue'

foreach ($port in 5000, 8080) {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if (-not $conn) {
        Write-Output ("port " + $port + ": free")
        continue
    }
    foreach ($procId in ($conn.OwningProcess | Sort-Object -Unique)) {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $procId) -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Output ("port " + $port + " -> pid " + $procId + " name=" + $proc.Name)
            Write-Output ("   cmdline: " + $proc.CommandLine)
        } else {
            Write-Output ("port " + $port + " pid " + $procId + " (process info unavailable)")
        }
    }
}