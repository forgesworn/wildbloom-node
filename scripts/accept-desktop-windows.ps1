param(
    [Parameter(Mandatory = $true)]
    [string] $BundleDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:RUNNER_TEMP) {
    throw "RUNNER_TEMP is required"
}

$installer = Get-ChildItem -Path $BundleDirectory -Recurse -File -Filter "*-setup.exe" |
    Select-Object -First 1
if (-not $installer) {
    throw "the Windows bundle does not contain an NSIS installer"
}

$installRoot = Join-Path $env:RUNNER_TEMP "wildbloom-node-install"
$runtimeRoot = Join-Path $env:RUNNER_TEMP "wildbloom-node-runtime"
New-Item -ItemType Directory -Force -Path $installRoot, $runtimeRoot | Out-Null

$install = Start-Process -FilePath $installer.FullName -ArgumentList @("/S", "/D=$installRoot") -Wait -PassThru
if ($install.ExitCode -ne 0) {
    throw "the NSIS installer exited with $($install.ExitCode)"
}

$application = Get-ChildItem -Path $installRoot -File -Filter "*.exe" |
    Where-Object { $_.Name -notmatch "(?i)uninstall" } |
    Select-Object -First 1
if (-not $application) {
    throw "the installed Wildbloom desktop executable is missing"
}

$torBinary = Get-ChildItem -Path $installRoot -Recurse -File -Filter "tor.exe" |
    Where-Object { $_.FullName -match "tor-runtime[\\/]tor[\\/]tor\.exe$" } |
    Select-Object -First 1
if (-not $torBinary) {
    throw "the installed Tor executable is missing"
}
$torVersion = & $torBinary.FullName --version
$torVersionText = $torVersion -join "`n"
if ($LASTEXITCODE -ne 0 -or $torVersionText -notmatch "^Tor version [0-9]+\.") {
    throw "the installed Tor executable did not report a valid version"
}

$applicationData = Join-Path $env:LOCALAPPDATA "dev.forgesworn.wildbloom-node"
$settingsDirectory = Join-Path $env:APPDATA "dev.forgesworn.wildbloom-node"
$settingsPath = Join-Path $settingsDirectory "settings.json"
New-Item -ItemType Directory -Force -Path $settingsDirectory | Out-Null
$settings = @{
    allowedPubkey = $null
    friendGrants = @()
    openShelter = $false
    quotaGib = 10
    startAtLogin = $false
    transport = "tor"
    directPort = 3742
    directPublicUrl = $null
} | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($settingsPath, $settings, [System.Text.UTF8Encoding]::new($false))
$stdout = Join-Path $runtimeRoot "app.stdout.log"
$stderr = Join-Path $runtimeRoot "app.stderr.log"
$applicationProcess = Start-Process -FilePath $application.FullName -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr

try {
    $hostnamePath = $null
    $databasePath = $null
    $nodeProcess = $null
    $nodePort = $null
    $ready = $false
    $deadline = (Get-Date).AddMinutes(6)
    while ((Get-Date) -lt $deadline) {
        $applicationProcess.Refresh()
        if ($applicationProcess.HasExited) {
            $errorOutput = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { "" }
            throw "the installed desktop process stopped before readiness: $errorOutput"
        }

        $hostnamePath = Get-ChildItem -Path $applicationData -Recurse -File -Filter "hostname" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "tor[\\/]onion-service[\\/]hostname$" } |
            Select-Object -First 1
        $databasePath = Get-ChildItem -Path $applicationData -Recurse -File -Filter "wildbloom.sqlite3" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        $nodeProcess = Get-CimInstance Win32_Process -Filter "Name = 'wildbloomd.exe'" |
            Where-Object { $_.ParentProcessId -eq $applicationProcess.Id } |
            Select-Object -First 1

        if ($nodeProcess -and $nodeProcess.CommandLine -match "--bind\s+127\.0\.0\.1:(\d+)") {
            $nodePort = [int] $Matches[1]
        }

        if ($hostnamePath -and $databasePath -and $nodePort) {
            $onion = (Get-Content -Path $hostnamePath.FullName -Raw).Trim()
            if ($onion -cmatch "^[a-z2-7]{56}\.onion$") {
                try {
                    $health = Invoke-RestMethod -Uri "http://127.0.0.1:$nodePort/healthz" -TimeoutSec 2
                    if ($health.storage.blobs -eq 0 -and
                        $health.storage.bytes -eq 0 -and
                        $health.storage.quota_bytes -eq 10737418240) {
                        $ready = $true
                        break
                    }
                }
                catch {
                    # The sidecar can appear in the process table just before HTTP readiness.
                }
            }
        }
        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        throw "the installed Windows desktop did not reach Tor and Blossom readiness"
    }

    $secondProcess = Start-Process -FilePath $application.FullName -PassThru
    if (-not $secondProcess.WaitForExit(20000)) {
        Stop-Process -Id $secondProcess.Id -Force
        throw "a second installed desktop instance remained running"
    }

    $matchingApplications = Get-CimInstance Win32_Process -Filter "Name = '$($application.Name)'" |
        Where-Object { $_.ExecutablePath -eq $application.FullName }
    if (@($matchingApplications).Count -ne 1) {
        throw "expected exactly one installed desktop process"
    }

    & taskkill.exe /PID $applicationProcess.Id /T /F | Out-Null
    $applicationProcess.WaitForExit(30000) | Out-Null
    Start-Sleep -Seconds 3

    $remainingChildren = Get-CimInstance Win32_Process |
        Where-Object { $_.ParentProcessId -eq $applicationProcess.Id }
    if ($remainingChildren) {
        throw "a bundled Tor or Wildbloom child remained after the desktop process tree stopped"
    }

    $uninstaller = Get-ChildItem -Path $installRoot -File -Filter "uninstall.exe" |
        Select-Object -First 1
    if (-not $uninstaller) {
        throw "the NSIS uninstaller is missing"
    }
    $uninstall = Start-Process -FilePath $uninstaller.FullName -ArgumentList "/S" -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) {
        throw "the NSIS uninstaller exited with $($uninstall.ExitCode)"
    }
    if (Test-Path $application.FullName) {
        throw "the desktop executable remained after uninstall"
    }
}
catch {
    if (Test-Path $stdout) {
        Get-Content -Path $stdout -ErrorAction SilentlyContinue | Select-Object -First 200 |
            ForEach-Object { [Console]::Error.WriteLine($_) }
    }
    if (Test-Path $stderr) {
        Get-Content -Path $stderr -ErrorAction SilentlyContinue | Select-Object -First 200 |
            ForEach-Object { [Console]::Error.WriteLine($_) }
    }
    throw
}
finally {
    if (-not $applicationProcess.HasExited) {
        & taskkill.exe /PID $applicationProcess.Id /T /F | Out-Null
    }
}

Write-Output "installed Windows desktop reached Tor and Blossom readiness, enforced one instance, stopped its children and uninstalled"
