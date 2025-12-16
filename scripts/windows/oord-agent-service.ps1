param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("sender", "receiver")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "python executable not found on PATH."
    exit 1
}

Write-Host "Starting Oord Agent ($Mode) with config '$ConfigPath'..."

python -m agent $Mode --config $ConfigPath
