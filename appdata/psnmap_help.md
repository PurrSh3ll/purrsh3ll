# Psnmap — Help

## Overview

Psnmap is a module for running Nmap scans directly from the application interface. It integrates with **WebMap**, a web-based Nmap results visualizer running inside a Docker container, allowing you to view scan reports in an interactive map.

---

## WebMap

**WebMap** is an open-source web application that visualizes Nmap XML scan results in a browser-based interface. It displays host details, open ports, services, and OS information in a clear, readable format.

- WebMap runs as a **Docker container** (`reborntc/webmap`) and is managed automatically by the application.
- Pressing the **network button** starts the container if it is not already running.
- WebMap loads XML files from the `appmodules/Cyb3rCollector/webmap/` folder — place your Nmap XML output there to have it appear in the interface.
- Access to WebMap is protected by a token. Use the **🔑 token button** to retrieve it. The token can be copied with a single click and used to log in to the WebMap interface.

---

## Running Scans

1. Select a scan **profile** from the dropdown list.
2. Enter the **target** (IP address, hostname, or range) in the target field.
3. Press **Enter** to run the command in the terminal, or **Paste** to insert it without executing.
4. Optionally, check **external terminal** to open the command in a standalone terminal window.

---

## Profiles

You can manage scan profiles directly in the module:

- **Add** your own custom Nmap commands to the profile list using the profile manager.
- **Edit** or **delete** existing profiles at any time.
- All profiles are stored inside the `.psnmap` file itself — no external configuration needed.

---

## History

Every executed command is automatically logged. Open the **history** tab to see a table of past runs, including the profile name, full command, and timestamp. The history is stored inside the `.psnmap` file alongside the profiles.

---

## .psnmap File

The `.psnmap` file is a JSON file that holds all persistent data for this module:

- `profiles` — list of saved scan profiles with name, command, and description
- `history` — log of all executed commands
- `port` — the port on which WebMap is served
