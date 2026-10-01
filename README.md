# LimiterNet

LimiterNet is a Windows desktop app for monitoring and limiting network traffic per application. It shows real-time download and upload activity, tracks active connections, and lets you set per-app limits or block network access entirely.

The app is built with Python, Flet, WinDivert, and standard Windows networking APIs. It is designed to help you control which processes are allowed to use bandwidth and at what rate.

## Features

- Live view of total inbound and outbound traffic
- Per-application activity tracking by process name
- Per-app download and upload limits
- Option to block all traffic for a selected app
- Search and filter for apps
- Active, rules, and connection tabs in the UI
- Persistent rules saved locally in the user AppData folder

## How it works

The application:

- scans current processes and active network connections
- matches socket activity to a process name
- records traffic statistics in real time
- applies a limiter when a rule is active
- blocks or throttles outbound and inbound packets using WinDivert

This behavior is implemented in the main process loop and rule engine in `main.py`.

## Requirements

- Windows 10 or Windows 11
- Administrator rights for packet filtering and traffic control
- Python environment with dependencies installed

Required packages:

```bash
pip install flet psutil pydivert pillow icoextract
```

The app also expects a valid WinDivert installation layer as used by `pydivert`.

## Run locally

From the project directory:

```bash
py main.py
```

If the app is run without administrative privileges, it attempts to relaunch itself elevated using the Windows shell.

## Package the app

This project already includes a packaging command used for building a Windows executable:

```bash
flet pack main.py \
  --name LimiterNet \
  --icon assets/favicon.ico \
  --add-data "assets:assets" \
  --uac-admin \
  --product-name LimiterNet \
  --product-version 1.0.0 \
  --file-version 1.0.0.0 \
  --file-description "Per-application network monitor and limiter"
```

This creates a packaged binary under the build or dist output directories depending on the environment setup.

## Configuration

Rules are stored at:

```text
%APPDATA%\LimiterNet\config.json
```

The app creates this directory automatically when a rule is saved.

## Project structure

- `main.py` – application logic, GUI, packet sniffing, and limiter engine
- `info.py` – app metadata, paths, and config path
- `assets/` – icons and bundled assets
- `dist/` and `build/` – generated packaging output

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.
