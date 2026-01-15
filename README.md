# MFASweep (Go Edition)

A cross-platform Go port of MFASweep that attempts to log in to various Microsoft services using a provided set of credentials and identifies if MFA is enabled.

> **Original Tool:** This is a Go port of [MFASweep](https://github.com/dafthack/MFASweep) by [@dafthack](https://github.com/dafthack) (Beau Bullock). The original PowerShell version and research can be found at the link above.

Depending on how conditional access policies and other multi-factor authentication settings are configured, some protocols may end up being left single factor. This tool helps identify those gaps.

## Features

MFASweep can test authentication against the following services:

* Microsoft Graph API
* Azure Service Management API
* Microsoft 365 Exchange Web Services (Basic Auth)
* Microsoft 365 Web Portal w/ 6 device types (Windows, Linux, MacOS, Android, iPhone, Windows Phone)
* Microsoft 365 Active Sync (Basic Auth)
* ADFS (if configured)

**WARNING: This tool attempts to login to the provided account multiple times. If you enter an incorrect password this may lock the account out.**

## Installation

Building from source:

```bash
# Build for current platform on windows or linux
go build -o mfasweep mfasweep.go

# Build for current platform on Windows
go build -o mfasweep.exe mfasweep.go

# Cross-compile
GOOS=windows GOARCH=amd64 go build -o mfasweep.exe mfasweep.go
GOOS=darwin GOARCH=amd64 go build -o mfasweep-macos mfasweep.go
GOOS=linux GOARCH=amd64 go build -o mfasweep-linux mfasweep.go
```

## Usage

### Run All Checks (10-11 auth attempts)

```bash
# Run all checks (10 attempts)
./mfasweep -username user@domain.com -password 'YourPassword' -all

# Run all checks including ADFS (11 attempts)
./mfasweep -username user@domain.com -password 'YourPassword' -all -include-adfs

# Skip confirmation prompt
./mfasweep -username user@domain.com -password 'YourPassword' -all -y
```

### Run Individual Checks (1 auth attempt each)

```bash
# Microsoft Graph API
./mfasweep -username user@domain.com -password 'YourPassword' -graph

# Azure Service Management API
./mfasweep -username user@domain.com -password 'YourPassword' -azure

# Exchange Web Services (Basic Auth)
./mfasweep -username user@domain.com -password 'YourPassword' -ews

# ActiveSync (Basic Auth)
./mfasweep -username user@domain.com -password 'YourPassword' -activesync

# ADFS / Federation check
./mfasweep -username user@domain.com -password 'YourPassword' -adfs

# Web Portal with specific User Agent
./mfasweep -username user@domain.com -password 'YourPassword' -web-ua Windows
./mfasweep -username user@domain.com -password 'YourPassword' -web-ua iPhone
```

### Run Web Portal Checks (6 auth attempts)

```bash
./mfasweep -username user@domain.com -password 'YourPassword' -web
```

### Recon Only (0 auth attempts)

Check if ADFS/federation is configured without attempting authentication:

```bash
./mfasweep -username user@domain.com -password dummy -recon
```

### Save Tokens

```bash
./mfasweep -username user@domain.com -password 'YourPassword' -all -write-tokens
```

Tokens will be saved to `AccessTokens.json`.

## Options

| Flag | Description |
|------|-------------|
| `-username` | Email address to authenticate with (required) |
| `-password` | Password for the account (required) |
| `-all` | Run all checks (10 auth attempts) |
| `-include-adfs` | Include ADFS when running -all (11 attempts) |
| `-graph` | Check Microsoft Graph API only |
| `-azure` | Check Azure Service Management API only |
| `-ews` | Check Exchange Web Services only |
| `-activesync` | Check ActiveSync only |
| `-adfs` | Check ADFS/Federation only |
| `-web` | Check M365 Web Portal with all user agents (6 attempts) |
| `-web-ua` | Check M365 Web Portal with specific UA (Windows/Linux/MacOS/Android/iPhone/WindowsPhone) |
| `-recon` | Check federation config only (no auth attempts) |
| `-write-tokens` | Save tokens to AccessTokens.json |
| `-y` | Skip confirmation prompt |
| `-verbose` | Enable verbose/debug output |

## Notes

- **Basic Auth Deprecation:** Microsoft has deprecated Basic Authentication for EWS and ActiveSync on most tenants. These checks may fail with 401 even with valid credentials.

- **Federated Domains:** For domains federated to external IdPs (CyberArk, Okta, etc.), the web portal checks may not work as authentication is redirected to the external IdP.

- **Managed Domains:** The web portal checks work best for domains where authentication is managed directly by Microsoft.

## Credits

- Original [MFASweep](https://github.com/dafthack/MFASweep) PowerShell tool by [Beau Bullock (@dafthack)](https://github.com/dafthack)
- Blog post: [Exploiting MFA Inconsistencies on Microsoft Services](https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/)

## License

MIT License (same as original)
