#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aegis-Tunnel X — Windows Native Demo
.DESCRIPTION
    Runs the full Aegis-Tunnel X system on loopback:
    1. Generates Kyber-768 + X25519 keypairs
    2. Starts server and client processes
    3. Sends test traffic through the tunnel
    4. Switches morphic profiles mid-stream
    5. Prints detection score dashboard
.NOTES
    Must be run from an Administrator PowerShell session.
    Requires: Python 3.12+, wintun.dll in project root
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Push-Location $ProjectRoot
try {
    Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         AEGIS-TUNNEL X  —  WINDOWS NATIVE DEMO       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    # Set OQS path for Kyber support
    $env:OQS_INSTALL_PATH = $ProjectRoot

    # 1. Generate keys
    Write-Host "[1/8] Generating cryptographic keys..." -ForegroundColor Yellow
    python -m aegis.cli keygen --output .\demo\keys\server
    python -m aegis.cli keygen --output .\demo\keys\client

    # Copy server public keys to client directory
    if (Test-Path .\demo\keys\server\kyber_pub.bin) {
        Copy-Item .\demo\keys\server\kyber_pub.bin  .\demo\keys\client\server_kyber_pub.bin -Force
    }
    if (Test-Path .\demo\keys\server\x25519_pub.bin) {
        Copy-Item .\demo\keys\server\x25519_pub.bin .\demo\keys\client\server_x25519_pub.bin -Force
    }
    Write-Host "  ✓ Keys generated`n" -ForegroundColor Green

    # 2. Start server
    Write-Host "[2/8] Starting tunnel server..." -ForegroundColor Yellow
    $server = Start-Process python -ArgumentList "-m aegis.cli server --config .\demo\server.conf" `
        -PassThru -NoNewWindow -RedirectStandardOutput .\demo\logs\server_stdout.log `
        -RedirectStandardError .\demo\logs\server_stderr.log
    Start-Sleep -Seconds 2
    Write-Host "  ✓ Server started (PID: $($server.Id))`n" -ForegroundColor Green

    # 3. Start client
    Write-Host "[3/8] Starting tunnel client..." -ForegroundColor Yellow
    $client = Start-Process python -ArgumentList "-m aegis.cli client --config .\demo\client.conf" `
        -PassThru -NoNewWindow -RedirectStandardOutput .\demo\logs\client_stdout.log `
        -RedirectStandardError .\demo\logs\client_stderr.log
    Start-Sleep -Seconds 3
    Write-Host "  ✓ Client started (PID: $($client.Id))`n" -ForegroundColor Green

    # 4. Wait for handshake
    Write-Host "[4/8] Waiting for tunnel handshake..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Write-Host "  ✓ Handshake window complete`n" -ForegroundColor Green

    # 5. Send ICMP test traffic
    Write-Host "[5/8] Sending ICMP test traffic..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 5; $i++) {
        $result = Test-Connection -ComputerName 10.10.0.1 -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "  Ping $($i+1)/5: Reply" -ForegroundColor Gray
        } else {
            Write-Host "  Ping $($i+1)/5: No reply (expected if TUN not fully routed)" -ForegroundColor DarkGray
        }
    }
    Write-Host ""

    # 6. List available profiles
    Write-Host "[6/8] Available morphic profiles:" -ForegroundColor Yellow
    python -m aegis.cli profile list
    Write-Host ""

    # 7. Switch profile
    Write-Host "[7/8] Switching to video_streaming profile..." -ForegroundColor Yellow
    python -m aegis.cli profile set video_streaming
    Start-Sleep -Seconds 2
    Write-Host ""

    # 8. Show status
    Write-Host "[8/8] Tunnel status:" -ForegroundColor Yellow
    python -m aegis.cli status
    Write-Host ""

    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                   DEMO COMPLETE                      ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green

} finally {
    # Cleanup
    Write-Host "`nCleaning up..." -ForegroundColor Yellow
    if ($server -and !$server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ Server stopped" -ForegroundColor Gray
    }
    if ($client -and !$client.HasExited) {
        Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ Client stopped" -ForegroundColor Gray
    }
    Pop-Location
}
