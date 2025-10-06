# Whitelist Proxy Documentation

## Overview
This Python-based proxy server operates on a strict whitelist principle: **all traffic is blocked by default** unless explicitly allowed. Designed for controlled environments requiring high security, the proxy logs all blocked requests and provides an intuitive interface for users to request whitelist access.

## Key Features
-**Default-Deny Policy**: Blocks all domains/IPs not on the whitelist
-**Comprehensive Logging**: Records timestamp, destination URL
-**User-Friendly Block Page**: Redirects HTTP requests to a custom portal for whitelist requests
-**Simple Configuration**: Manage whitelist via editable `whitelist.json` file

## How It Works
1. **Request Interception**: Intercepts all HTTP/HTTPS traffic
2. **Whitelist Check**: Compares requested domain against `whitelist.json`
3. **Action**:
   -**Allowed**: Proxies request to destination
   -**Blocked**:
     - Logs request details to `blocked_requests.log`
     - For HTTP sites: Serves custom portal page
     - For HTTPS sites: Returns 403 Forbidden

## Installation
```bash
git clone https://github.com/M4XR0HDE/Proxy.git
cd Proxy
pip install -r requirements.txt (not yet implemented)
```

## Configuration
Edit `whitelist.json` (one domain per line):
```
[
    "python.org",
    "github.com",
]
```

## Usage
Start the proxy:
```bash
python whitelist_proxy.py
```

Configure your device to use:
- IP: `127.0.0.1`
- Port: `8080` (or your configured port)

## Whitelist Request Portal
When accessing blocked HTTP sites, users see a responsive portal where they can:
- View blocked domain
- Submit access requests
- Provide justification

Requests are stored in the Proxy folder inside "whitelist_requests" with the request to read and a file to add it the whitelist.

## Security Notes
- HTTPS requests are blocked without decryption
- No persistent user data storage
- Regular log rotation recommended
- Run as non-root user in production

---
