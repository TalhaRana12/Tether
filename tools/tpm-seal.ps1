<#
.SYNOPSIS
  Seal / unseal the Ed25519 release seed under a non-exportable TPM RSA key.

.DESCRIPTION
  HR-0.2 wants the release key on offline hardware with a physical touch. This is the
  zero-budget substitute, and it is a substitute rather than an equal - see
  docs/FREE-TIER-SUBSTITUTIONS.md section 4 and the deviation note at HR-0.2.

  WHY RSA WRAPS AN ED25519 SEED RATHER THAN SIGNING DIRECTLY
  --------------------------------------------------------
  Verified on this machine, not assumed: the Windows TPM (Microsoft Platform Crypto
  Provider) CANNOT create an Ed25519 key. CngKey.Create with ED25519 returns "The
  requested operation is not supported." It offers RSA.

  Signing with a TPM RSA key would keep the key non-exportable but break HR-4.1's
  pinned EdDSA and force a rewrite of the agent verifier that is already written and
  tested. So instead the Ed25519 seed - 256 bits of CSPRNG output, satisfying HR-0.3 -
  is ENCRYPTED AT REST under a TPM RSA key that cannot leave this machine.

  WHAT THIS BUYS
  --------------
    CI cannot sign ......................... kept in full
    blob is useless on another machine ..... kept - only this TPM can unwrap it
    malware running as you cannot get it ... LOST, the seed is in memory while signing
    physical touch per signature ........... LOST

  The third and fourth are why HR-0.2 carries a deviation note and why builds must not
  be distributed to anyone else yet.

.EXAMPLE
  # One time, at the ceremony:
  $pub = tools\sign-release\target\release\tether-sign-release.exe keygen 2>seed.hex
  Get-Content seed.hex | .\tools\tpm-seal.ps1 -Seal
  Remove-Item seed.hex          # the sealed blob is the only copy from here on

.EXAMPLE
  # Every release:
  .\tools\tpm-seal.ps1 -Unseal | tether-sign-release.exe sign dist\manifest.json
#>
[CmdletBinding(DefaultParameterSetName = 'Unseal')]
param(
    [Parameter(ParameterSetName = 'Seal')]   [switch]$Seal,
    [Parameter(ParameterSetName = 'Unseal')] [switch]$Unseal,
    [Parameter(ParameterSetName = 'Info')]   [switch]$Info,

    # Seed accepted either on the pipeline or as -SeedHex. Never as a bare positional
    # argument: PowerShell records command lines in transcripts and history, and a secret
    # in argv is visible to any local process reading the process list.
    [Parameter(ParameterSetName = 'Seal', ValueFromPipeline = $true)]
    [string]$SeedHex,

    [string]$KeyName = 'tether-release-wrap',
    [string]$BlobPath = 'keys/release-seed.tpm-sealed'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

# Resolve the blob path against the REPO ROOT, not the caller's working directory.
# A signing ceremony run from the wrong folder should fail loudly on the TPM, not
# silently look for the sealed seed somewhere it was never written.
if (-not [System.IO.Path]::IsPathRooted($BlobPath)) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $BlobPath = Join-Path $repoRoot $BlobPath
}

function Get-WrapKey {
    param([switch]$CreateIfMissing)
    $provider = New-Object System.Security.Cryptography.CngProvider('Microsoft Platform Crypto Provider')

    if ([System.Security.Cryptography.CngKey]::Exists($KeyName, $provider)) {
        return [System.Security.Cryptography.CngKey]::Open($KeyName, $provider)
    }
    if (-not $CreateIfMissing) {
        throw "TPM key '$KeyName' does not exist. Run with -Seal first."
    }

    $p = New-Object System.Security.Cryptography.CngKeyCreationParameters
    $p.Provider = $provider
    # NOT exportable. This is the whole point: the wrapping key is generated inside the
    # TPM and the TPM will not hand it back, so the sealed blob is bound to this machine.
    $p.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $p.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
    $p.Parameters.Add((New-Object System.Security.Cryptography.CngProperty(
        'Length', [BitConverter]::GetBytes(2048),
        [System.Security.Cryptography.CngPropertyOptions]::None)))

    Write-Host 'Creating a non-exportable TPM RSA wrapping key...' -ForegroundColor Cyan
    return [System.Security.Cryptography.CngKey]::Create(
        [System.Security.Cryptography.CngAlgorithm]::Rsa, $KeyName, $p)
}

if ($Info) {
    $provider = New-Object System.Security.Cryptography.CngProvider('Microsoft Platform Crypto Provider')
    $exists = [System.Security.Cryptography.CngKey]::Exists($KeyName, $provider)
    Write-Host "TPM wrapping key '$KeyName' : $(if ($exists) { 'present' } else { 'ABSENT' })"
    Write-Host "sealed seed blob            : $(if (Test-Path $BlobPath) { (Resolve-Path $BlobPath).Path } else { 'ABSENT' })"
    if ($exists) {
        $k = [System.Security.Cryptography.CngKey]::Open($KeyName, $provider)
        Write-Host "export policy               : $($k.ExportPolicy)  (None = the TPM will not release it)"
        $k.Dispose()
    }
    return
}

if ($Seal) {
    $raw = if ($SeedHex) { $SeedHex } else { ($input | Out-String) }
    # Extract the 64-hex token rather than trusting the whole string. PowerShell decorates
    # native-command stderr with the command name, so a naive .Trim() picks up that noise
    # and the seed silently fails to parse.
    $m = [regex]::Match($raw, '(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])')
    if (-not $m.Success) {
        throw "No 64-hex-character seed found in the input ($($raw.Length) chars supplied)."
    }
    $hex = $m.Value
    $seed = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) { $seed[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }

    $key = Get-WrapKey -CreateIfMissing
    $rsa = New-Object System.Security.Cryptography.RSACng($key)
    # OAEP-SHA256, not PKCS#1 v1.5: v1.5 padding has a long history of decryption oracles.
    $blob = $rsa.Encrypt($seed, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)

    $dir = Split-Path -Parent $BlobPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    [System.IO.File]::WriteAllBytes($BlobPath, $blob)

    [Array]::Clear($seed, 0, $seed.Length)
    $rsa.Dispose(); $key.Dispose()

    Write-Host "Sealed to $BlobPath ($($blob.Length) bytes)." -ForegroundColor Green
    Write-Host 'This blob is safe to commit: it only opens on this machine TPM.'
    Write-Host 'Now DELETE the plaintext seed. There is no recovery copy (HR-4.5 shape).'
    return
}

# Default: unseal to stdout, for piping straight into the signer. Never written to disk.
if (-not (Test-Path $BlobPath)) { throw "No sealed blob at $BlobPath. Run -Seal first." }
$blob = [System.IO.File]::ReadAllBytes($BlobPath)
$key = Get-WrapKey
$rsa = New-Object System.Security.Cryptography.RSACng($key)
$seed = $rsa.Decrypt($blob, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
$hex = ($seed | ForEach-Object { $_.ToString('x2') }) -join ''
[Array]::Clear($seed, 0, $seed.Length)
$rsa.Dispose(); $key.Dispose()
Write-Output $hex
