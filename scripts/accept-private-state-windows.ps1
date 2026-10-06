# Hosted Windows test. Uses synthetic data and a disposable unprivileged account.
# Verifies actual access denial, as well as rejection of tampered ACLs.
$ErrorActionPreference = 'Stop'
$probe = (Resolve-Path 'target/debug/examples/permissions.exe').Path
$root = Join-Path $env:PUBLIC ('wildbloom-acl-' + [Guid]::NewGuid().ToString('N'))
$account = 'wb' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
$password = [Guid]::NewGuid().ToString('N') + '!aA7'
$created = $false
function Probe([string]$operation, [string]$path, [bool]$success) {
    & $probe $operation $path 2>$null
    if (($LASTEXITCODE -eq 0) -ne $success) { throw "Unexpected private-state result: $operation" }
}
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    # The test parent/control is deliberately readable by any authenticated user.
    & icacls.exe $root /grant '*S-1-5-11:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set control ACL' }
    $control = Join-Path $root 'control.txt'
    [IO.File]::WriteAllText($control, 'public control')
    $state = Join-Path $root 'owner'
    Probe create $state $true
    Probe directory $state $true
    Probe directory (Join-Path $state 'work') $true
    Probe file (Join-Path $state 'receipt.json') $true
    New-LocalUser -Name $account -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires | Out-Null
    $created = $true
    Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class PrivateStateAccess {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern uint SetNamedSecurityInfo(string path, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    public static void NullDacl(string path) {
        if (SetNamedSecurityInfo(path, 1, 0x80000004, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) != 0)
            throw new Exception("Cannot inject synthetic null DACL");
    }
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static void Verify(string user, string password, string control, string root) {
        IntPtr token;
        if (!LogonUser(user, ".", password, 2, 0, out token)) throw new Exception("Test account logon failed");
        try {
            if (!ImpersonateLoggedOnUser(token)) throw new Exception("Test impersonation failed");
            try {
                if (File.ReadAllText(control) != "public control") throw new Exception("Control read failed");
                foreach (string name in new [] {"receipt.json", "work/pool-report.json", "work/coded-0"}) {
                    string path = Path.Combine(root, name);
                    bool readDenied = false, writeDenied = false;
                    try { File.ReadAllBytes(path); } catch (UnauthorizedAccessException) { readDenied = true; }
                    try { using (File.Open(path, FileMode.Open, FileAccess.Write)) {} }
                    catch (UnauthorizedAccessException) { writeDenied = true; }
                    if (!readDenied || !writeDenied) throw new Exception("Private file accessible to second account");
                }
            } finally { if (!RevertToSelf()) Environment.FailFast("Cannot restore test identity"); }
        } finally { CloseHandle(token); }
    }
}
'@
    [PrivateStateAccess]::Verify($account, $password, $control, $state)
    Write-Output 'PASS: second account reads public control but cannot read or write receipt, report or coded part'
    $receipt = Join-Path $state 'receipt.json'
    & icacls.exe $receipt /grant '*S-1-1-0:R' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inject broad file ACL' }
    Probe file $receipt $false
    [PrivateStateAccess]::NullDacl($receipt)
    Probe file $receipt $false
    & icacls.exe $state /grant '*S-1-1-0:(OI)(CI)R' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inject broad directory ACL' }
    Probe directory $state $false
    Write-Output 'PASS: broad file/directory ACLs and null DACL are refused'
    # A junction must be rejected even when its destination is otherwise private.
    $target = Join-Path $root 'target'
    Probe create $target $true
    $link = Join-Path $root 'junction'
    New-Item -ItemType Junction -Path $link -Target $target | Out-Null
    Probe directory $link $false
    [IO.Directory]::Delete($link)
    Write-Output 'PASS: Windows junction refused'
} finally {
    if ($created) { Remove-LocalUser -Name $account }
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
# The last probe deliberately failed. Do not leak its expected native exit code
# into GitHub's PowerShell wrapper after every assertion and cleanup succeeded.
$global:LASTEXITCODE = 0
