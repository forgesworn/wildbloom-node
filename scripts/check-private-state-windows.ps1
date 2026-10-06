# Independent ACL inspection of actual native desktop state. No contents/paths logged.
$ErrorActionPreference = 'Stop'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($user, 'S-1-5-18', 'S-1-5-32-544')
$item = Get-Item -LiteralPath $env:WILDBLOOM_PRIVATE_PATH -Force
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Private state is a reparse point' }
$acl = Get-Acl -LiteralPath $item.FullName
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'Unexpected state owner' }
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (-not $rules.Count) { throw 'Missing private ACL' }
$ownerFull = $false
foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -notin $allowed -or $rule.AccessControlType -ne 'Allow') { throw 'Unexpected state access rule' }
    if ($rule.IdentityReference.Value -eq $user -and
        ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) {
        $ownerFull = $true
    }
}
if (-not $ownerFull) { throw 'Owner full access missing' }
