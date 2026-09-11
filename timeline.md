# Timeline – System32 Masquerading Investigation

## Timeline Overview

The timeline reconstructs the creation, execution, and SIEM observation of the controlled masquerading-style artifact.

The timestamps below are based on the observed lab evidence. No timestamps are invented for actions where an exact time was not recorded.

---

## Investigation Timeline

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

## Detailed Timeline

### Baseline

The investigation began by identifying the host and current user:

```text
Hostname:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell
```

PowerShell version:

```text
7.6.6
```

The investigation was performed on:

```text
11 September 2026
```

---

### Legitimate Binary Baseline

The original source binary was:

```text
C:\Windows\System32\notepad.exe
```

Observed SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The executable had a valid Authenticode signature.

This established the known-good source used to create the controlled artifact.

---

### Controlled Masquerading Artifact

The source binary was copied and renamed:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

The artifact retained the Notepad binary content.

Its SHA256 was:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

This matched the original Notepad binary.

---

### File Creation – Sysmon Event ID 11

At:

```text
11-09-2026 07:41:12
```

Sysmon Event ID 11 recorded creation of:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

This established the first significant forensic event involving the masquerading-style artifact.

---

### File Metadata Comparison

The lab artifact had:

```text
Length:
360448 bytes

CreationTime:
11-09-2026 07:41:12

LastWriteTime:
09-09-2026 09:56:13
```

The legitimate Windows `svchost.exe` had:

```text
Length:
88312 bytes

CreationTime:
31-08-2026 04:13:21

LastWriteTime:
31-08-2026 04:13:21
```

The differences supported the conclusion that the two files were not the same binary.

---

### Hash Comparison

Legitimate Windows `svchost.exe`:

```text
1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2
```

Lab `svchost.exe`:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The lab hash matched the original `notepad.exe`.

This established the actual binary identity.

---

### Process Execution – Sysmon Event ID 1

The renamed binary was executed using:

```powershell
Start-Process "C:\System32MasqueradingLab\Payload\svchost.exe"
```

At:

```text
11-09-2026 08:20:29
```

Sysmon Event ID 1 recorded process creation.

The execution path was:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

This confirmed that the trusted-looking filename was not merely present on disk; it was executed.

---

### Wazuh Correlation

At:

```text
Sep 11, 2026 @ 08:20:30.158
```

Wazuh ingested the corresponding process event.

Important fields included:

```text
Agent:
001

Agent Name:
DESKTOP-9MMM37V

Image:
C:\System32MasqueradingLab\Payload\svchost.exe

Command Line:
C:\System32MasqueradingLab\Payload\svchost.exe

Description:
Notepad

Company:
Microsoft Corporation

File Version:
10.0.26100.9278 (WinBuild.160101.0800)

Integrity Level:
High
```

The approximately one-second difference between Sysmon and Wazuh timestamps is consistent with telemetry collection and processing.

---

## Evidence Sequence

```text
Legitimate notepad.exe
        ↓
Hash and signature baseline
        ↓
Copied to lab directory
        ↓
Renamed to svchost.exe
        ↓
Sysmon Event ID 11
        ↓
File metadata comparison
        ↓
Hash comparison
        ↓
Execute lab svchost.exe
        ↓
Sysmon Event ID 1
        ↓
Wazuh process telemetry
        ↓
Filename / metadata mismatch
        ↓
Masquerading-style anomaly confirmed
        ↓
Benign laboratory verdict
```

---

## Key Timeline Findings

### 1. File Creation

The masquerading-style artifact was created at:

```text
11-09-2026 07:41:12
```

### 2. File Identity

The artifact named `svchost.exe` had the same SHA256 as the original `notepad.exe`.

### 3. Process Execution

Execution was observed at:

```text
11-09-2026 08:20:29
```

through Sysmon Event ID 1.

### 4. SIEM Correlation

Wazuh recorded the execution at:

```text
08:20:30.158
```

### 5. Metadata Mismatch

Wazuh identified the binary description as:

```text
Notepad
```

despite the filename being:

```text
svchost.exe
```

---

## Final Timeline Assessment

The timeline establishes a complete evidence chain:

```text
File Creation
     ↓
File Identity Validation
     ↓
Process Execution
     ↓
Sysmon Detection
     ↓
Wazuh Correlation
     ↓
Binary Metadata Analysis
```

The resulting conclusion is:

```text
Confirmed masquerading-style filename/path anomaly
+
Benign controlled laboratory activity
```

The timeline demonstrates why process investigations should correlate file-system activity, process creation, binary identity, and SIEM telemetry rather than relying on a process name alone.
