param([Parameter(Mandatory=$true)][string]$Target)
$ErrorActionPreference = 'Stop'
$tool = Get-ChildItem "${env:ProgramFiles(x86)}/Windows Kits/10/bin/*/x64/signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $tool) { throw 'Windows SDK signtool missing' }
$files = @(Get-Item "desktop/src-tauri/binaries/wildbloomd-$Target.exe")
$files += @(Get-ChildItem desktop/src-tauri/tor-runtime -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' })
if ($files.Count -lt 2) { throw 'Daemon or Tor runtime missing' }
foreach ($file in $files) {
    & $tool.FullName sign /sha1 $env:WINDOWS_CERTIFICATE_THUMBPRINT /fd SHA256 /tr $env:WINDOWS_TIMESTAMP_URL /td SHA256 $file.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Runtime signing failed' }
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $env:WINDOWS_CERTIFICATE_THUMBPRINT -or -not $signature.TimeStamperCertificate) {
        throw 'Runtime signature, expected signer or timestamp verification failed'
    }
}
