---
title: Antivirus
description: ClamAV-powered file scanning for Localitas
---

# Antivirus

Scan files for malware using ClamAV.

## Prerequisites

On macOS the app installs ClamAV with Homebrew on first launch if it is missing. It configures clamd and freshclam for virus definition updates. The clamd daemon must be running for scans to work.

## Scanning Uploaded Files

Upload a file via multipart form to have it scanned immediately. The scan is recorded in your history with its verdict. The uploaded file itself is not kept, clean or infected.

**POST /api/scan-file** - Upload and scan a file (multipart, field name: `file`; needs write scope)

## Scanning a Folder

Scan every file under a directory on the host, skipping names that match the exclude globs. Only core's system token may call this route; it is what the nightly scan uses.

**POST /api/scan-folder** - Scan a host directory (`{"path": "...", "exclude": ["*.log"]}`)

## Scan History

View past scan results including verdict, threat name, file size, and scan duration. You see your own scans; admins also see the nightly system scans.

**GET /api/history** - List scan history (supports `limit` and `offset` query params)

## Status

Check ClamAV installation status, daemon health, virus definition version, and aggregate scan statistics.

**GET /api/status** - Returns installation state, version, total scans, threats found, and clean file counts

## Verdicts

Each scan produces one of two verdicts:
- **clean** - No threats detected
- **infected** - Threat detected; the threat name is recorded

## Automation

The app serves a nightly job in its `cron.json`, which core's automation runs: `cron:antivirus:scan-folder` calls `POST /api/scan-folder` at 02:00 on every node and scans the Localitas data directory (`LOCALITAS_DATA_DIR`, default `~/.localitas`), skipping `raft`, `bleve-indices`, `logs`, SQLite database files and log files.

## Build & Deploy

Run these in the app's repository, `~/localitas-app-antivirus`.

### Version

```bash
bin/antivirus-server --version
```

### Build from source

```bash
# Native binary
go build -o bin/antivirus-server ./cmd/antivirus-server

# Native binary plus the Linux amd64 binary the Docker image is built from (antivirus-server-linux-amd64)
make build-linux
```

`make lint` runs gofmt and go vet; `make test` runs them and then the tests. `make build` runs only the lint step.

### Run natively

```bash
make start   # writes the launchd service com.localitas.app.antivirus for bin/antivirus-server and loads it on port 9211
make stop
make logs    # follows ~/.localitas/logs/antivirus/stdout.log
```

The app announces itself to core when it starts, and core serves it at `/apps/ext/antivirus/`.

### Docker

```bash
make build-docker   # builds the Linux binary and the antivirus:latest image
make start-docker   # runs container "antivirus" on port 9211, labelled localitas.app=true, with the host's clamd socket mounted
make stop-docker
make logs-docker
```

Core registers containers labelled `localitas.app=true` once Docker reports them healthy.

### Publish

```bash
# Run the tests, build the image, push ghcr.io/localitas/localitas-app-antivirus:latest and :<VERSION>
make docker-push

# Build dist/antivirus-server-darwin-arm64 and dist/antivirus-server-darwin-amd64
# and create GitHub release vX.Y.Z on this repository with them
make release VERSION=vX.Y.Z
```

`VERSION` defaults to `git describe --tags --always --dirty`.

### Download

Pre-built macOS binaries are on the [releases page](https://github.com/localitas/localitas-app-antivirus/releases):
- `antivirus-server-darwin-arm64` (Apple Silicon)
- `antivirus-server-darwin-amd64` (Intel)

Every push to `main` publishes a release: `.github/workflows/release.yml` runs the tests and releases both binaries as `v0.1.<commit count>.<UTC timestamp>`. `make release` publishes one by hand.

Download with the GitHub CLI:

    gh release download --repo localitas/localitas-app-antivirus --pattern 'antivirus-server-*'
