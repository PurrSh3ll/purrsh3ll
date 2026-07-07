# Psnmap — Help

## Overview

Psnmap is a module for running Nmap scans directly from the application interface. It integrates with **WebMap**, a web-based Nmap results visualizer running inside a Docker container, so you can view scan reports in an interactive map.

---

## Controls

Toolbar buttons:

- **⚙ Settings** — configure scan **profiles** (add, edit, delete, clear) and the WebMap **port**.
- **🔑 Token** — retrieve the WebMap access token; copy it with one click to log in to the WebMap interface.
- **🌐 / ⛔ Network** — start the WebMap Docker container (**🌐**); the icon turns to **⛔** while it is running, and pressing it again lets you stop it.
- **visualization** — switch the central view to the WebMap report; use **← Back** to return to the scan configuration.
- **help** — show this page.

---

## WebMap

**WebMap** is an open-source web application that visualizes Nmap XML scan results in a browser-based interface. It displays host details, open ports, services, and OS information in a clear, readable format.

- WebMap runs as a **Docker container** (`reborntc/webmap`) and is managed automatically by the application.
- Pressing the **🌐 network button** starts the container if it is not already running.
- WebMap loads XML files from the `appmodules/Cyb3rCollector/webmap/` folder. Enable **WebMap Export** (see below) so scan results are written there and appear in the interface.
- Access is protected by a token — use the **🔑 token button** to retrieve and copy it.

---

## Running Scans

1. Select a scan **profile** from the dropdown list.
2. Enter the **target** (IP address, hostname, or range) in the target field.
3. The command is assembled in the input line at the bottom. Press **⏎** to run it, or **⧉** to paste it into the terminal without executing.
4. Adjust behaviour with the checkboxes:
   - **External Terminal** — run the command in a separate, standalone terminal window.
   - **Keep Session** — reuse the current terminal session instead of opening a new tab. (Mutually exclusive with External Terminal.)
   - **WebMap Export** — also save the scan's XML output to the WebMap folder so it shows up in the visualizer. (Not available while External Terminal is on.)

---

## Profiles

Manage scan profiles from the **⚙ settings button**:

- **Add** your own custom Nmap commands to the profile list.
- **Edit** or **delete** existing profiles, or **Clear profiles** to remove them all.
- Profiles are stored inside the `.purr` file itself — no external configuration needed.

---

## The .purr File

The `psnmap.purr` file is a JSON file that holds all persistent data for this module:

- `profiles` — list of saved scan profiles (name, command, description)
- `port` — the host port on which WebMap is served
