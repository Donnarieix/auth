param(
    [switch]$Bootstrap
)
$ErrorActionPreference = 'Stop'
$env:AUTH_PUBLIC_ORIGIN = 'http://127.0.0.1:3000'
if ($env:OIDC_SIGNING_KEY_FILE -or $env:OIDC_SIGNING_KID) {
    throw 'Remove explicit signing-key variables to use the isolated development key.'
}
if ($env:SMTP_HOST) {
    Write-Host 'SMTP is configured: emails will use the configured provider.'
} else {
    Write-Host 'Development email outbox: data/outbox'
}
if ($Bootstrap) {
    cargo run -- admin bootstrap operator
} else {
    cargo run
}
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
