---
title: Antivirus
description: ClamAV-powered file scanning for Localitas
---

# Antivirus

Scan uploaded and managed files for malware using ClamAV.

## Prerequisites

The app installs ClamAV automatically on first launch. It configures clamd and freshclam for virus definition updates. The clamd daemon must be running for scans to work.

## Scanning Uploaded Files

Upload a file via multipart form to have it scanned immediately. Clean files are moved to managed storage under `downloads/{user_id}/{filename}`. Infected files are rejected and not stored.

**POST /api/scan** - Upload and scan a file (multipart, field name: `file`)

## Scanning Managed Files

Scan a file already stored in the filesystem app by providing its path.

**POST /api/scan-managed** - Scan a file by path (`{"path": "..."}`)

**POST /api/scan-managed-all** - Scan all files in managed storage at once

## Scan History

View past scan results including verdict, threat name, file size, and scan duration.

**GET /api/history** - List scan history (supports `limit` and `offset` query params)

## Status

Check ClamAV installation status, daemon health, virus definition version, and aggregate scan statistics.

**GET /api/status** - Returns installation state, version, total scans, threats found, and clean file counts

## Verdicts

Each scan produces one of two verdicts:
- **clean** - No threats detected, file is safe
- **infected** - Threat detected, file is quarantined

## Automation

The antivirus app supports automated scanning through the Localitas automation system. Configure scan schedules to periodically check managed files for new threats.

## Build & Deploy

### Version

```bash
./antivirus-server --version
```

### Build from source

```bash
# Development (native)
cd apps/antivirus && go build -o bin/antivirus-server ./cmd/antivirus-server

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o bin/antivirus-server-linux-amd64 ./cmd/antivirus-server
```

### Docker

Build a Docker image directly from the binary:

```bash
# Default base image (debian:12-slim)
./antivirus-server docker-build

# Custom base image
./antivirus-server docker-build --base ubuntu:24.04

# Custom Dockerfile
./antivirus-server docker-build --dockerfile ./my.Dockerfile

# Tag and push to registry
./antivirus-server docker-build --tag ghcr.io/localitas/antivirus:latest --push
```

The `docker-build` command requires a Linux amd64 binary in the same directory. Run `make deploy-build` from the project root first.

### Download

Pre-built binaries are available on the [GitHub releases page](https://github.com/localitas/localitas/releases).

Each release includes three builds per app:
- `antivirus-server-darwin-arm64` (macOS Apple Silicon)
- `antivirus-server-linux-amd64` (Linux x86_64)
- `antivirus-server-linux-arm64` (Linux ARM64)

Download with the GitHub CLI:

    gh release download --repo localitas/localitas --pattern 'antivirus-server-*'

### Release

All app binaries are published to GitHub releases as part of `make deploy-upload-image`.
