<#
  Aegis-Tunnel X — One-click launcher
  Starts Dashboard, Server, and Client in separate windows.
  Press Ctrl+C in this window to stop all three.
#>

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║       AEGIS-TUNNEL X  LAUNCHER       ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$py = "C:\Users\graph\AppData\Local\Programs\Python\Python311\python.exe"

# --- 1. Dashboard ---
Write-Host "[1/3] Starting Dashboard..." -ForegroundColor Green
$dashboard = Start-Process -PassThru -FilePath $py `
    -ArgumentList "$projectDir\dashboard\app.py" `
    -WorkingDirectory $projectDir `
    -WindowStyle Normal

Start-Sleep -Seconds 2   # give Flask time to bind port 5000

# --- 2. Server ---
Write-Host "[2/3] Starting Server..." -ForegroundColor Green
$server = Start-Process -PassThru -FilePath $py `
    -ArgumentList "$projectDir\server.py" `
    -WorkingDirectory $projectDir `
    -WindowStyle Normal

Start-Sleep -Seconds 2   # give server time to listen on TCP 9000

# --- 3. Client ---
Write-Host "[3/3] Starting Client..." -ForegroundColor Green
$client = Start-Process -PassThru -FilePath $py `
    -ArgumentList "$projectDir\client.py" `
    -WorkingDirectory $projectDir `
    -WindowStyle Normal

Write-Host ""
Write-Host "  All components running!" -ForegroundColor Yellow
Write-Host "  Dashboard : http://127.0.0.1:5000" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Press ENTER here to stop everything..." -ForegroundColor Magenta
Write-Host ""

# Block until user presses Enter
Read-Host | Out-Null

# --- Cleanup ---
Write-Host "Shutting down..." -ForegroundColor Red

foreach ($proc in @($dashboard, $server, $client)) {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  Stopped PID $($proc.Id)" -ForegroundColor DarkGray
    }
}

Write-Host "Done." -ForegroundColor Green
