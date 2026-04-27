#Requires -RunAsAdministrator
param(
    [switch]$CleanupOnExit
)

<#
.SYNOPSIS
    Aegis-Tunnel X - Windows Native Demo
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

    Default behavior keeps server/client running after the demo.
    Pass -CleanupOnExit to restore auto-cleanup behavior.
#>

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

# --------------------------------------------------------
# Python executable path
# --------------------------------------------------------
$PyPath = "C:\Users\graph\AppData\Local\Programs\Python\Python311\python.exe"

Push-Location $ProjectRoot
try {
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "         AEGIS-TUNNEL X  -  WINDOWS NATIVE DEMO        " -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""

    # Set environment for OQS and UTF-8 output
    $env:OQS_INSTALL_PATH = $ProjectRoot
    $env:PYTHONIOENCODING = "utf-8"
    $env:PYTHONWARNINGS = "ignore"

    # Ensure log directory exists
    New-Item -ItemType Directory -Force -Path ".\demo\logs" | Out-Null

    # --------------------------------------------------------
    # 1. Generate keys
    # --------------------------------------------------------
    Write-Host "[1/8] Generating cryptographic keys..." -ForegroundColor Yellow
    & $PyPath -W ignore -m aegis.cli keygen --output .\demo\keys\server 2>&1 | Where-Object { $_ -notmatch "UserWarning|from oqs" }
    & $PyPath -W ignore -m aegis.cli keygen --output .\demo\keys\client 2>&1 | Where-Object { $_ -notmatch "UserWarning|from oqs" }

    # Copy server public keys to client directory
    if (Test-Path .\demo\keys\server\kyber_pub.bin) {
        Copy-Item .\demo\keys\server\kyber_pub.bin  .\demo\keys\client\server_kyber_pub.bin -Force
    }
    if (Test-Path .\demo\keys\server\x25519_pub.bin) {
        Copy-Item .\demo\keys\server\x25519_pub.bin .\demo\keys\client\server_x25519_pub.bin -Force
    }
    Write-Host "  [OK] Keys generated" -ForegroundColor Green
    Write-Host ""

    # --------------------------------------------------------
    # 2. Start server
    # --------------------------------------------------------
    Write-Host "[2/8] Starting tunnel server..." -ForegroundColor Yellow
    $server = Start-Process $PyPath `
        -ArgumentList "-W ignore -m aegis.cli server --config .\demo\server.conf" `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput .\demo\logs\server_stdout.log `
        -RedirectStandardError  .\demo\logs\server_stderr.log
    Start-Sleep -Seconds 3
    if ($server.HasExited) {
        Write-Host "  [FAIL] Server exited prematurely. Stderr:" -ForegroundColor Red
        if (Test-Path .\demo\logs\server_stderr.log) {
            Get-Content .\demo\logs\server_stderr.log -Tail 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        }
    } else {
        Write-Host "  [OK] Server started (PID: $($server.Id))" -ForegroundColor Green
    }
    Write-Host ""

    # --------------------------------------------------------
    # 3. Start client
    # --------------------------------------------------------
    Write-Host "[3/8] Starting tunnel client..." -ForegroundColor Yellow
    $client = Start-Process $PyPath `
        -ArgumentList "-W ignore -m aegis.cli client --config .\demo\client.conf" `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput .\demo\logs\client_stdout.log `
        -RedirectStandardError  .\demo\logs\client_stderr.log
    Start-Sleep -Seconds 3
    if ($client.HasExited) {
        Write-Host "  [FAIL] Client exited prematurely. Stderr:" -ForegroundColor Red
        if (Test-Path .\demo\logs\client_stderr.log) {
            Get-Content .\demo\logs\client_stderr.log -Tail 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        }
    } else {
        Write-Host "  [OK] Client started (PID: $($client.Id))" -ForegroundColor Green
    }
    Write-Host ""

    # --------------------------------------------------------
    # 4. Wait for handshake
    # --------------------------------------------------------
    Write-Host "[4/8] Waiting for tunnel handshake..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Write-Host "  [OK] Handshake window complete" -ForegroundColor Green
    Write-Host ""

    # --------------------------------------------------------
    # 5. Send ICMP test traffic
    # --------------------------------------------------------
    Write-Host "[5/8] Sending ICMP test traffic to 10.10.0.1 ..." -ForegroundColor Yellow
    $pingSuccess = 0
    for ($i = 0; $i -lt 5; $i++) {
        $result = Test-Connection -ComputerName 10.10.0.1 -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "  Ping $($i+1)/5: Reply" -ForegroundColor Green
            $pingSuccess++
        } else {
            Write-Host "  Ping $($i+1)/5: No reply" -ForegroundColor DarkGray
        }
    }
    if ($pingSuccess -gt 0) {
        Write-Host "  [OK] $pingSuccess/5 pings replied" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] No ping replies. Checking process status..." -ForegroundColor DarkYellow

        if ($server -and -not $server.HasExited) {
            Write-Host "  Server is running (PID: $($server.Id))" -ForegroundColor Gray
        } elseif ($server) {
            Write-Host "  [FAIL] Server has exited! Stderr:" -ForegroundColor Red
            if (Test-Path .\demo\logs\server_stderr.log) {
                Get-Content .\demo\logs\server_stderr.log -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
            }
        }
        if ($client -and -not $client.HasExited) {
            Write-Host "  Client is running (PID: $($client.Id))" -ForegroundColor Gray
        } elseif ($client) {
            Write-Host "  [FAIL] Client has exited! Stderr:" -ForegroundColor Red
            if (Test-Path .\demo\logs\client_stderr.log) {
                Get-Content .\demo\logs\client_stderr.log -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
            }
        }
    }
    Write-Host ""

    # --------------------------------------------------------
    # 6. List profiles
    # --------------------------------------------------------
    Write-Host "[6/8] Available morphic profiles:" -ForegroundColor Yellow
    & $PyPath -W ignore -m aegis.cli profile list 2>&1 | Where-Object { $_ -notmatch "UserWarning|from oqs" }
    Write-Host ""

    # --------------------------------------------------------
    # 7. Switch profile
    # --------------------------------------------------------
    Write-Host "[7/8] Switching to video_streaming profile..." -ForegroundColor Yellow
    & $PyPath -W ignore -m aegis.cli profile set video_streaming 2>&1 | Where-Object { $_ -notmatch "UserWarning|from oqs" }
    Write-Host ""

    # --------------------------------------------------------
    # 8. Show status
    # --------------------------------------------------------
    Write-Host "[8/8] Tunnel status:" -ForegroundColor Yellow
    Start-Sleep -Seconds 2  # Wait for status file to update with traffic stats
    & $PyPath -W ignore -m aegis.cli status 2>&1 | Where-Object { $_ -notmatch "UserWarning|from oqs" }
    Write-Host ""

    Write-Host "======================================================" -ForegroundColor Green
    Write-Host "                   DEMO COMPLETE                       " -ForegroundColor Green
    Write-Host "======================================================" -ForegroundColor Green

} finally {
    Write-Host ""
    if ($CleanupOnExit) {
        # Cleanup
        Write-Host "Cleaning up..." -ForegroundColor Yellow
        if ($server -and -not $server.HasExited) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Server stopped" -ForegroundColor Gray
        }
        if ($client -and -not $client.HasExited) {
            Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Client stopped" -ForegroundColor Gray
        }
        # Clean up routes (silently ignore errors)
        & route DELETE 10.10.0.1 2>&1 | Out-Null
        & route DELETE 10.10.0.2 2>&1 | Out-Null
        # Remove status file
        $statusFile = Join-Path $env:USERPROFILE ".aegis\status.json"
        if (Test-Path $statusFile) { Remove-Item $statusFile -Force -ErrorAction SilentlyContinue }
    } else {
        Write-Host "Keeping server/client running (no cleanup)." -ForegroundColor Green
        if ($server -and -not $server.HasExited) {
            Write-Host "  Server PID: $($server.Id)" -ForegroundColor Gray
        }
        if ($client -and -not $client.HasExited) {
            Write-Host "  Client PID: $($client.Id)" -ForegroundColor Gray
        }
        Write-Host "  Logs: .\\demo\\logs\\server_stdout.log and .\\demo\\logs\\client_stdout.log" -ForegroundColor Gray
        Write-Host "  To cleanup later, rerun script with -CleanupOnExit or stop PIDs manually." -ForegroundColor Gray
    }
    Pop-Location
}