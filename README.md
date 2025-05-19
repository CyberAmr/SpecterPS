# SpecterPS

**SpecterPS** is a lightweight PowerShell reverse shell Command & Control (C2) server designed for penetration testers and red teamers. It generates obfuscated, base64-encoded payloads for stealthy remote access and allows managing multiple clients via an interactive shell. Easy to use, effective, and perfect for Windows environments.

---

## Features

- Generate obfuscated PowerShell reverse shell payloads  
- Base64-encoded payloads for stealth and evasion  
- Manage multiple connected clients  
- Interactive PowerShell shell with selected client  
- Simple, single Python script  

---

## Requirements

- Python 3.x  
- Target machine must have PowerShell (v5 or higher recommended)  

---

## Usage

Run the server by executing `python3 specterps.py`. At the prompt, use commands such as `help` to view available commands, `generate <ip> <port>` to create an obfuscated PowerShell payload, `list` to show connected clients, `select <id>` to choose a client, `shell` to open an interactive shell with the selected client, and `exit` to stop the server. After generating the payload, run it on the target Windows machine’s PowerShell prompt to establish a connection. You can then interact with the connected client through the interactive shell.

---

## Disclaimer

Use only in authorized and legal environments. Unauthorized use is illegal and unethical.
