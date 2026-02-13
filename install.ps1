# Snag installer script for Windows
# Usage: powershell -c "irm https://abzolute1.github.io/snag/install.ps1 | iex"

$ErrorActionPreference = "Stop"

$Repo = "Abzolute1/snag"
$BinaryName = "snag"
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"

# --- Output helpers ---

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error-And-Exit {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
    exit 1
}

# --- Architecture detection ---

function Get-Arch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"  { return "x86_64" }
        "Arm64" {
            Write-Error-And-Exit "ARM64 Windows is not yet supported. Check https://github.com/$Repo/releases"
        }
        default {
            Write-Error-And-Exit "Unsupported architecture: $arch. Check https://github.com/$Repo/releases"
        }
    }
}

# --- Fetch latest release version ---

function Get-LatestVersion {
    Write-Info "Fetching latest release version..."

    try {
        $response = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 403) {
            Write-Error-And-Exit "GitHub API rate limit exceeded. Wait a few minutes or download directly from https://github.com/$Repo/releases"
        }
        elseif ($status -eq 404) {
            Write-Error-And-Exit "No releases found for $Repo. The project may not have published a release yet."
        }
        elseif ($status) {
            Write-Error-And-Exit "GitHub API returned HTTP $status. Try downloading from https://github.com/$Repo/releases"
        }
        else {
            Write-Error-And-Exit "Network error: could not reach GitHub API. Check your internet connection."
        }
    }

    $tag = $response.tag_name
    if (-not $tag) {
        Write-Error-And-Exit "Failed to parse version from GitHub API response"
    }

    # Strip leading 'v' if present
    $version = $tag -replace '^v', ''
    return $version
}

# --- Download and install ---

function Install-Binary {
    $arch = Get-Arch
    $version = Get-LatestVersion

    Write-Info "Detected system: windows-$arch"
    Write-Info "Latest version: v$version"

    $assetName = "$BinaryName-windows-$arch.exe.zip"
    $downloadUrl = "https://github.com/$Repo/releases/download/v$version/$assetName"

    Write-Info "Downloading from: $downloadUrl"

    # Create temp directory
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "snag-install-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        $downloadFile = Join-Path $tmpDir $assetName

        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadFile -UseBasicParsing
        }
        catch {
            Write-Error-And-Exit "Download failed. No binary available for windows-$arch. Check https://github.com/$Repo/releases for available platforms."
        }

        if (-not (Test-Path $downloadFile) -or (Get-Item $downloadFile).Length -eq 0) {
            Write-Error-And-Exit "Downloaded file is empty or missing"
        }

        # Extract zip
        Write-Info "Extracting binary..."
        $extractDir = Join-Path $tmpDir "extract"
        try {
            Expand-Archive -Path $downloadFile -DestinationPath $extractDir -Force
        }
        catch {
            Write-Error-And-Exit "Failed to extract archive. The download may be corrupted - try again."
        }

        $exePath = Join-Path $extractDir "$BinaryName.exe"
        if (-not (Test-Path $exePath)) {
            Write-Error-And-Exit "Expected binary '$BinaryName.exe' not found in archive"
        }

        # Verify the binary runs
        try {
            $downloadedVersion = & $exePath --version 2>&1
            Write-Info "Verified: $downloadedVersion"
        }
        catch {
            Write-Error-And-Exit "Downloaded binary failed to execute. It may be built for a different platform."
        }

        # Install to per-user directory (no admin needed)
        $installDir = Join-Path $env:LOCALAPPDATA "Programs\snag"
        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        $destPath = Join-Path $installDir "$BinaryName.exe"
        Write-Info "Installing to $destPath..."
        Copy-Item -Path $exePath -Destination $destPath -Force

        # Add to PATH if not already present
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$installDir*") {
            Write-Info "Adding $installDir to user PATH..."
            $newPath = "$userPath;$installDir"
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            # Also update current session so the binary is immediately available
            $env:Path = "$env:Path;$installDir"
            Write-Warn "PATH updated. Restart your terminal for the change to take effect in new sessions."
        }

        # Verify installation
        try {
            $null = Get-Command $BinaryName -ErrorAction Stop
            Write-Info "Successfully installed $BinaryName v$version!"
            Write-Info "Run '$BinaryName --help' to get started"
        }
        catch {
            Write-Warn "Installation complete, but '$BinaryName' is not found in PATH"
            Write-Warn "You may need to restart your terminal or add $installDir to your PATH manually"
        }
    }
    finally {
        # Cleanup temp directory
        if (Test-Path $tmpDir) {
            Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Main ---

Write-Info "Installing $BinaryName..."

# Check PowerShell version (need 5.0+ for Expand-Archive)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error-And-Exit "PowerShell 5.0 or later is required. Current version: $($PSVersionTable.PSVersion)"
}

Install-Binary
