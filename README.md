# pivOT

**pivOT** is a Python-based red team utility that identifies potential network pivots to OT (Operational Technology) environments. It does so by:

1. Checking remote registry keys for hardcoded OT IP addresses or subnets.  
2. Using WMI/DCOM to execute commands (e.g., `netstat -ano`) and identifying active connections to OT subnets.  
3. Enumerating domain machines via LDAP if no targets are specified.  
4. Supporting **pass-the-hash** or **password-based** authentication.  
5. Including a `--debug` mode for verbose logging.

By combining registry lookups and netstat analysis, **pivOT** offers a *non-invasive* way to detect which systems may have routes or references to OT networks, all without deploying heavier or riskier payloads.

---

## Table of Contents

- [Features](#features)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Quickstart & Usage](#quickstart--usage)  
- [OPSEC Considerations](#opsec-considerations)  
- [Event Logs & Detection](#event-logs--detection)  
- [FAQ](#faq)

---

## Features

- **Non-Invasive Enumeration**  
  - Scans registry keys and netstat output without installing or injecting advanced payloads.  
- **WMI/DCOM Command Execution**  
  - Relies on Windows built-in WMI/DCOM for remote command execution; no additional services required.  
- **LDAP Enumeration**  
  - Optionally gathers all domain computers if no target list is provided.  
- **Pass-the-Hash & Kerberos Support**  
  - Authenticate via either user password or NTLM hashes; optional Kerberos fallback.  
- **Colorized & Structured Output**  
  - Results are displayed in color-coded format and can also be saved as JSON/CSV.

---

## Prerequisites

1. **Local Administrator Rights**  
   - Remote registry access and WMI/DCOM execution both require the scanning account to have local administrator privileges on the target.  
2. **Python 3** and `pip` or a Python virtual environment.  
3. **Impacket Libraries** (and dependencies)  
   - e.g., `pip install impacket ldap3 colorama`.  
4. **Network Reachability** to the target on SMB (TCP 445) for file transfers and remote registry.  
5. **Valid Domain Credentials** (or pass-the-hash).  

---

## Installation

1. **Clone This Repo**  
   ```bash
   git clone https://github.com/loosehose/pivOT.git
   cd pivOT
   ```
2. **Install Python Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```
   > *Alternatively, use a Python virtual environment to keep dependencies isolated.*

3. **Run**  
   ```bash
   python pivOT.py --help
   ```

---

## Quickstart & Usage

Below is a minimal usage example to scan one target with password-based auth:

```bash
python pivOT.py \
  --domain CORP.local \
  --username Administrator \
  --password 'SuperSecureP@ss' \
  --target winhost.corp.local \
  --ot-subnets 10.10.0.0/16 192.168.100.0/24
```

### Common Arguments

| Argument                   | Description                                                                                       |
|---------------------------|---------------------------------------------------------------------------------------------------|
| `-d, --domain`            | Domain name for SMB/DCOM/LDAP operations (required).                                             |
| `-u, --username`          | User account for authentication (required).                                                      |
| `-p, --password`          | Password (omit if using pass-the-hash).                                                          |
| `-H, --hashes`            | Pass-the-hash (`LM:NT` or `:NT` format).                                                         |
| `-k, --kerberos`          | Use Kerberos (requires valid TGT or password).                                                   |
| `--dc-ip`                 | IP of Domain Controller for LDAP or Kerberos (optional).                                         |
| `-t, --target`            | Single target host.                                                                              |
| `-f, --targets-file`      | File with multiple targets (one per line).                                                       |
| `--ldap-enum`             | Enumerate domain computers via LDAP if no targets are specified.                                 |
| `--threads`               | Number of parallel threads (default 5).                                                          |
| `--no-registry`           | Skip registry checks.                                                                            |
| `--no-netstat`            | Skip netstat checks.                                                                             |
| `--ot-subnets`            | One or more subnets (e.g. `10.10.0.0/16`) to look for.                                           |
| `--output-format`         | Save results as JSON or CSV.                                                                     |
| `--output-file`           | Output filename for saved results.                                                               |
| `--debug`                 | Enable verbose debug logs.                                                                       |

### Example: Pass-the-Hash, LDAP Enumeration, and JSON Output

```bash
python pivOT.py \
  --domain CORP.local \
  --username Administrator \
  --hashes :5fbaa...deadbeef \
  --ldap-enum \
  --dc-ip 10.0.0.5 \
  --ot-subnets 10.10.0.0/16 10.10.14.0/24 \
  --output-format json \
  --output-file results.json \
  --debug
```

This enumerates all domain-joined machines, scans their registries and netstat output for any references to `10.10.0.0/16` or `10.10.14.0/24`, and saves the findings in `results.json`.

---

## OPSEC Considerations

1. **Logs & Artifacts**  
   - The script writes a small `.log` file to the `ADMIN$` share on each target to capture netstat output. We then read that file back via SMB. That filename is randomized but can still be found in security logs.
2. **Use of `cmd.exe /Q /c`**  
   - By default, pivOT executes netstat via:  
     ```batch
     cmd.exe /Q /c netstat -ano > \\127.0.0.1\ADMIN$\tmp_XXXXXX.log
     ```
   - This can trigger detection rules that look for specific `cmd.exe /c` patterns in event logs.  
   - **Alternative Execution**  
     - You can modify the script to invoke PowerShell or rename `cmd.exe` to reduce detectability (e.g., use `rundll32`, `wmic /OUTPUT:`, or `powershell.exe -Command netstat -ano`).  
     - Consider updating the command line in the function `wmi_exec_command` if your threat model requires lower detectability.  
3. **Event Logs**  
   - **Process Execution** (Event ID `4688`) may be generated on the target when netstat is invoked via WMI.  
   - **Remote Registry** requests can generate logs such as Event ID `5145` (if logging is enabled) or other access events.  
   - **SMB Logon Events** (e.g., `4624`, `4648`) may appear if the environment monitors SMB authentications.  
5. **Admin Rights Required**  
   - Remote registry and WMI/DCOM both require local admin privileges on the target. This is normal but will raise typical Windows security events if auditing is configured.  
5. **Recommended Usage**  
   - For stealth, minimize concurrency (`--threads`) and possibly randomize or slow your scans to reduce log volume.  
   - If you are worried about detection on the remote host, consider alternate output filenames and share usage.

---

## Event Logs & Detection

- **Windows Event ID `4624`**: A successful account logon (SMB).
- **Windows Event ID `4688`**: A new process (netstat) was created.
- **Windows Event ID `5145`**: A network share object was accessed.
- **WMI-specific** logs in the **Event Viewer > Applications and Services Logs > Microsoft > Windows > WMI-Activity** (`Operational`).  
- **Anti-Virus / EDR** solutions may flag suspicious WMI usage or remote registry queries.

---

## FAQ

**Q:** _Does pivOT need to install anything on the remote host?_  
**A:** No. It uses built-in Windows services (SMB, WMI, Remote Registry) and only writes a small temporary file to `ADMIN$`.

**Q:** _Why can’t I see OT references on some hosts?_  
**A:** The user might not have local admin privileges. Or the host simply doesn’t store references in the registry or netstat. Also, netstat only shows active connections.

**Q:** _Does pivOT scan everything in the registry?_  
**A:** It specifically targets `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`. You can extend or modify this path in the script if needed.

---

## Contributing

Pull requests and issues are welcome! If you have feature ideas or find bugs, please open an issue.

---

### Disclaimer

This tool is provided for authorized red teaming, penetration testing, or educational purposes **only**. Always adhere to your engagement’s rules of engagement and obtain proper permissions before scanning or interacting with any network assets.

---

## License

MIT License. See the [LICENSE](LICENSE.md) file for details.
