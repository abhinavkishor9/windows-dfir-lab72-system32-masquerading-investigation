# Timeline 

| Time | Source | Event | Significance |
|---|---|---|---|
| 11 Sep 2026 | PowerShell | Host and user baseline established | Confirmed investigation environment |
| 11 Sep 2026 | PowerShell | Lab directory created | Established controlled investigation location |
| 11 Sep 2026 | PowerShell | Legitimate `notepad.exe` identified | Established benign source binary |
| 11 Sep 2026 | PowerShell | Notepad SHA256 collected | Established binary baseline |
| 11 Sep 2026 | PowerShell | Notepad Authenticode signature validated | Confirmed signed source binary |
| 11 Sep 2026 07:41:12 | Sysmon Event ID 11 | `svchost.exe` created | File creation observed |
| 11 Sep 2026 | PowerShell | Lab artifact metadata and hash collected | Established suspicious file characteristics |
| 11 Sep 2026 | PowerShell | Legitimate `svchost.exe` compared with lab artifact | Confirmed path, size, and hash differences |
| 11 Sep 2026 08:20:29 | Sysmon Event ID 1 | Lab `svchost.exe` executed | Execution confirmed |
| 11 Sep 2026 08:20:30.158 | Wazuh | Process execution ingested | SIEM correlation confirmed |
| 11 Sep 2026 | Wazuh | Description identified binary as `Notepad` | Filename/metadata mismatch confirmed |
| 11 Sep 2026 | PowerShell | Evidence files exported | Investigation artifacts preserved |

---

