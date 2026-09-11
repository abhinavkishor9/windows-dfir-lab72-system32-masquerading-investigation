# Windows DFIR Lab 72 – System32 Masquerading Investigation

## Overview

This lab investigates a Windows masquerading scenario where a benign executable is renamed to a trusted Windows process name and executed from an unexpected directory.

The lab uses `notepad.exe` as the benign source binary and creates a controlled copy named `svchost.exe` under a dedicated lab directory. The investigation then validates the executable using its path, file metadata, SHA256 hash, digital signature, Sysmon telemetry, process creation data, and Wazuh evidence.

The key DFIR principle demonstrated in this lab is:

> **A filename is an indicator, not an identity.**

A process named `svchost.exe` should not automatically be considered legitimate. Its location, binary identity, execution context, parent process, command line, hash, signature, and timeline must also be validated.

---

## Scenario

During a Windows endpoint investigation, a process named `svchost.exe` is observed executing from:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

The filename resembles a legitimate Windows system process, but the executable is not located in the normal:

```text
C:\Windows\System32\
```

directory.

To reproduce and investigate this behavior safely, a copy of the legitimate Windows `notepad.exe` binary was created inside the controlled lab directory and renamed to `svchost.exe`.

The investigation focuses on determining whether the executable is actually the Windows Service Host binary or simply a different executable using a trusted filename.

---

## Lab Objectives

- Understand Windows executable masquerading.
- Identify trusted-looking filenames executing from unexpected directories.
- Establish a legitimate System32 baseline.
- Create a controlled masquerading artifact without modifying System32.
- Compare legitimate and suspicious executable paths.
- Compare file sizes and SHA256 hashes.
- Validate Authenticode signatures.
- Detect file creation using Sysmon Event ID 11.
- Detect process execution using Sysmon Event ID 1.
- Investigate process command-line and executable-path information.
- Correlate endpoint telemetry through Wazuh.
- Identify filename and binary metadata mismatches.
- Build a timeline from file and process events.
- Distinguish a masquerading-style anomaly from confirmed malicious activity.

---

## Lab Environment

| Component | Details |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| User | `desktop-9mmm37v\dell` |
| Date | 11 September 2026 |
| Operating System | Windows |
| PowerShell | 7.6.6 |
| Sysmon | Installed and collecting telemetry |
| Wazuh Agent | `001` |
| Lab Directory | `C:\System32MasqueradingLab` |

---

## Lab Structure

```text
C:\System32MasqueradingLab\
├── Payload\
│   └── svchost.exe
└── Evidence\
    ├── process-evidence.txt
    ├── file-metadata.txt
    ├── hash.txt
    └── signature.txt
```

---

## Investigation Workflow

```text
Establish baseline
        ↓
Identify legitimate notepad.exe
        ↓
Create controlled copy
        ↓
Rename copy to svchost.exe
        ↓
Place executable outside System32
        ↓
Compare path / size / hash
        ↓
Validate digital signature
        ↓
Sysmon Event ID 11
        ↓
Execute renamed binary
        ↓
Sysmon Event ID 1
        ↓
Validate process information
        ↓
Correlate Wazuh telemetry
        ↓
Build timeline
        ↓
Determine final verdict
```

---

## 1. Establish Windows Baseline

The investigation begins by confirming the host and PowerShell environment.

```powershell
hostname
whoami
$PSVersionTable.PSVersion
Get-Date
```

Observed environment:

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
PowerShell: 7.6.6
Date: 11 September 2026
```

---

## 2. Create the Controlled Lab Directory

A dedicated directory was created so that the experiment did not modify or replace any real Windows System32 executable.

```powershell
$Lab = "C:\System32MasqueradingLab"

New-Item -Path $Lab -ItemType Directory -Force
New-Item -Path "$Lab\Payload" -ItemType Directory -Force
New-Item -Path "$Lab\Evidence" -ItemType Directory -Force
```

The resulting structure was:

```text
C:\System32MasqueradingLab\
├── Payload\
└── Evidence\
```

---

## 3. Identify the Legitimate Source Binary

The legitimate Windows Notepad executable was identified at:

```text
C:\Windows\System32\notepad.exe
```

File metadata was collected before creating the controlled copy.

```powershell
$Source = "C:\Windows\System32\notepad.exe"

Get-Item $Source |
    Select-Object FullName, Length, CreationTime, LastWriteTime
```

Observed:

```text
Path:
C:\WINDOWS\System32\notepad.exe

Length:
360448 bytes
```

The SHA256 hash was also collected:

```powershell
Get-FileHash $Source -Algorithm SHA256
```

Observed SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

---

## 4. Validate the Source Signature

The source executable was checked using Authenticode validation.

```powershell
Get-AuthenticodeSignature $Source |
    Select-Object Status, StatusMessage, SignerCertificate
```

Observed:

```text
Status:
Valid

StatusMessage:
Signature verified.
```

This established that the source file was a valid digitally signed Windows executable before the controlled copy was created.

---

## 5. Create the Masquerading Artifact

The legitimate `notepad.exe` was copied into the lab directory and renamed to `svchost.exe`.

```powershell
Copy-Item `
    "C:\Windows\System32\notepad.exe" `
    "$Lab\Payload\svchost.exe"
```

The resulting file was:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

No real System32 file was replaced or modified.

---

## 6. Compare the Legitimate and Lab Executables

The legitimate Windows `svchost.exe` was compared with the controlled lab artifact.

### Legitimate executable

```text
Path:
C:\Windows\System32\svchost.exe

Length:
88312 bytes

SHA256:
1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2
```

### Lab executable

```text
Path:
C:\System32MasqueradingLab\Payload\svchost.exe

Length:
360448 bytes

SHA256:
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The hashes are different.

The lab file's SHA256 is identical to the original `notepad.exe` hash, proving that the file content is Notepad rather than the legitimate Service Host executable.

---

## 7. Compare File Metadata

The controlled artifact was inspected using PowerShell.

```powershell
Get-Item "$Lab\Payload\svchost.exe" |
    Select-Object FullName, Length, CreationTime, LastWriteTime
```

Observed:

```text
FullName:
C:\System32MasqueradingLab\Payload\svchost.exe

Length:
360448

CreationTime:
11-09-2026 07:41:12

LastWriteTime:
09-09-2026 09:56:13
```

The legitimate System32 `svchost.exe` had:

```text
Length:
88312

CreationTime:
31-08-2026 04:13:21

LastWriteTime:
31-08-2026 04:13:21
```

The path and file characteristics clearly distinguish the lab artifact from the legitimate Windows Service Host binary.

---

## 8. Validate the Lab File Hash

The hash of the renamed executable was collected again after creation.

```powershell
Get-FileHash "$Lab\Payload\svchost.exe" -Algorithm SHA256
```

Observed:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

This matched the original `notepad.exe` hash.

Therefore:

```text
svchost.exe filename
        ≠
svchost.exe binary identity
```

The filename was changed, but the underlying executable content remained Notepad.

---

## 9. Validate the Digital Signature

The renamed executable was also checked for Authenticode validation.

```powershell
Get-AuthenticodeSignature "$Lab\Payload\svchost.exe" |
    Select-Object Status, StatusMessage
```

The file retained the valid signature inherited from the original Microsoft-signed executable.

This demonstrates an important investigation point:

> A valid digital signature does not automatically make an execution context legitimate.

The binary may be authentic while its filename, location, execution context, or purpose is suspicious.

---

## 10. Detect File Creation with Sysmon

Sysmon Event ID 11 was reviewed for the creation of the renamed executable.

Observed event:

```text
Event ID: 11
Time: 11-09-2026 07:41:12

File:
C:\System32MasqueradingLab\Payload\svchost.exe
```

Event ID 11 provided the file-creation evidence linking the suspicious-looking filename to its creation in the unexpected directory.

---

## 11. Execute the Renamed Binary

The controlled executable was launched from the lab directory.

```powershell
Start-Process "$Lab\Payload\svchost.exe"
```

This generated process-creation telemetry.

---

## 12. Detect Process Execution with Sysmon

Sysmon Event ID 1 was observed for the execution.

Observed:

```text
Event ID: 1
Time: 11-09-2026 08:20:29
```

The process execution was associated with:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

This was the key process-level evidence confirming that the trusted-looking filename was actually executed from the non-standard directory.

---

## 13. Investigate Running Processes

A basic process-name search was performed:

```powershell
Get-Process svchost
```

Multiple legitimate `svchost.exe` processes were returned because Windows normally runs many Service Host processes.

This demonstrates why a simple process-name search is insufficient for masquerading investigations.

The investigation therefore moved from:

```text
Process Name
```

to:

```text
Executable Path
Command Line
Hash
Signature
Parent Process
User
Timeline
```

A more targeted process query was used:

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.ExecutablePath -like "*System32MasqueradingLab*"
    } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

The output was exported for evidence preservation:

```text
C:\System32MasqueradingLab\Evidence\process-evidence.txt
```

---

## 14. Capture File Evidence

The following evidence files were created:

```text
C:\System32MasqueradingLab\Evidence\process-evidence.txt
C:\System32MasqueradingLab\Evidence\file-metadata.txt
C:\System32MasqueradingLab\Evidence\hash.txt
C:\System32MasqueradingLab\Evidence\signature.txt
```

These artifacts preserve the main evidence collected during the investigation.

---

## 15. Wazuh Correlation

The execution was also observed in Wazuh.

Relevant Wazuh event details:

```text
Timestamp:
Sep 11, 2026 @ 08:20:30.158

Agent:
001

Agent Name:
DESKTOP-9MMM37V

Command Line:
C:\System32MasqueradingLab\Payload\svchost.exe

Image:
C:\System32MasqueradingLab\Payload\svchost.exe

Current Directory:
C:\Windows\System32\

Company:
Microsoft Corporation

Description:
Notepad

File Version:
10.0.26100.9278 (WinBuild.160101.0800)

Integrity Level:
High
```

The Wazuh telemetry is especially useful because the executable filename and embedded binary metadata do not agree.

The file is named:

```text
svchost.exe
```

but its metadata identifies it as:

```text
Notepad
```

The SHA256 also matches the original `notepad.exe`:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

---

## Evidence Correlation

| Evidence | Observation | Interpretation |
|---|---|---|
| Filename | `svchost.exe` | Trusted Windows process name |
| Expected path | `C:\Windows\System32\` | Normal location for legitimate binary |
| Actual path | `C:\System32MasqueradingLab\Payload\svchost.exe` | Unexpected location |
| Lab file size | `360448` bytes | Different from legitimate svchost |
| Legitimate svchost size | `88312` bytes | Normal System32 baseline |
| Lab SHA256 | `468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E` | Matches Notepad |
| Legitimate svchost SHA256 | `1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2` | Different binary |
| Sysmon Event ID 11 | File created | Creation observed |
| Sysmon Event ID 1 | Process created | Execution observed |
| Wazuh Description | `Notepad` | Binary metadata mismatch |
| Wazuh Image | Lab `svchost.exe` path | Execution from unexpected directory |
| Signature | Valid | Binary is authentically signed |
| Lab purpose | Controlled test | Benign laboratory activity |

---

## Investigation Findings

### Finding 1 – Trusted Filename

The executable was named:

```text
svchost.exe
```

which is associated with a legitimate Windows system process.

### Finding 2 – Unexpected Location

The executable was located under:

```text
C:\System32MasqueradingLab\Payload\
```

rather than:

```text
C:\Windows\System32\
```

### Finding 3 – Hash Mismatch

The legitimate `svchost.exe` and the lab artifact have different SHA256 hashes.

### Finding 4 – Binary Identity

The lab artifact's SHA256 matched the original `notepad.exe`.

This establishes that the file content was Notepad despite its `svchost.exe` filename.

### Finding 5 – Metadata Mismatch

Wazuh identified the file description as:

```text
Notepad
```

while the filename was:

```text
svchost.exe
```

This provides strong evidence of filename masquerading.

### Finding 6 – Execution Confirmed

Sysmon Event ID 1 and Wazuh telemetry confirmed execution of:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

### Finding 7 – File Creation Confirmed

Sysmon Event ID 11 recorded creation of the renamed executable.

---

## Final Verdict

**Confirmed masquerading-style filename/path anomaly — benign laboratory activity.**

The artifact intentionally used the trusted `svchost.exe` filename while containing the `notepad.exe` binary and residing outside the legitimate System32 directory.

The evidence confirms the masquerading behavior, but there is no indication that this laboratory artifact represents real malware.

---

## SOC Investigation Takeaway

A trusted process name should never be treated as proof of legitimacy.

For Windows masquerading investigations, validate:

```text
Name
  ↓
Path
  ↓
Process
  ↓
Parent Process
  ↓
Command Line
  ↓
Hash
  ↓
Digital Signature
  ↓
User
  ↓
Timeline
```

The most important lesson from this lab is:

> **Filename is an indicator, not an identity.**

---

## MITRE ATT&CK Relevance

This lab demonstrates the investigation concept associated with **Masquerading**, where an executable attempts to appear legitimate by using a trusted name, location, or other identifying characteristics.

Relevant investigation telemetry includes:

- Windows process creation
- File creation
- Executable path
- Command line
- File hash
- Digital signature
- Parent process
- User context
- Process metadata
- SIEM correlation

---

## Tools Used

- Windows PowerShell
- Sysmon
- Wazuh
- Windows Event Logs
- `Get-FileHash`
- `Get-AuthenticodeSignature`
- `Get-CimInstance`
- Windows process inspection

---

## Evidence

The investigation generated the following local evidence files:

```text
Evidence/
├── process-evidence.txt
├── file-metadata.txt
├── hash.txt
└── signature.txt
```

---

## Conclusion

This lab demonstrated how a SOC analyst can investigate a trusted-looking Windows executable without relying on the filename alone. By correlating path, metadata, hash, signature, Sysmon file and process events, and Wazuh telemetry, the investigation established that the `svchost.exe` artifact was actually a renamed copy of `notepad.exe`. The activity was intentionally generated for the lab, resulting in a confirmed masquerading-style anomaly but a benign final verdict.
