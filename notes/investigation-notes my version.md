# Investigation Notes 

## 1. Initial Suspicion

The suspicious-looking executable was located at:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

The filename is associated with the legitimate Windows Service Host process, which normally executes from:

```text
C:\Windows\System32\svchost.exe
```

The unexpected path was therefore treated as the initial detection indicator.

The unusual path alone did not prove malicious activity.

---

## 2. Legitimate svchost.exe Baseline

The legitimate Windows binary was inspected:

```text
C:\Windows\System32\svchost.exe
```

Observed:

```text
Length:
88312 bytes

SHA256:
1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2
```

The legitimate file's timestamps were:

```text
Creation:
31-08-2026 04:13:21

LastWrite:
31-08-2026 04:13:21
```

This provided the baseline for comparison.

---

## 3. Suspicious Artifact

The lab artifact was:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

Observed:

```text
Length:
360448 bytes

Creation:
11-09-2026 07:41:12

LastWrite:
09-09-2026 09:56:13
```

The file size was already inconsistent with the legitimate `svchost.exe`.

---

## 4. Hash Analysis

The suspicious file was hashed using SHA256.

```text
SHA256:
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

This hash matched the original:

```text
C:\Windows\System32\notepad.exe
```

Therefore, the suspicious filename did not represent the actual binary identity.

Comparison:

| File | SHA256 |
|---|---|
| Legitimate `svchost.exe` | `1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2` |
| Lab `svchost.exe` | `468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E` |
| Original `notepad.exe` | `468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E` |

### Finding

The lab `svchost.exe` is a renamed copy of `notepad.exe`.

---

## 5. Digital Signature Analysis

The original Notepad executable was checked using:

```powershell
Get-AuthenticodeSignature "C:\Windows\System32\notepad.exe"
```

Observed:

```text
Status:
Valid

StatusMessage:
Signature verified.
```

The renamed copy retained the valid signature.

### Interpretation

The signature confirms that the underlying executable is an authentic signed Microsoft binary.

However:

```text
Valid signature
        ≠
Legitimate execution context
```

The executable was still suspicious from a process-investigation perspective because its trusted-looking filename did not match its actual location or binary identity.

---

## 6. Sysmon File Creation Evidence

Sysmon Event ID 11 recorded creation of the artifact.

```text
Event ID:
11

Time:
11-09-2026 07:41:12

File:
C:\System32MasqueradingLab\Payload\svchost.exe
```

This established the creation point in the investigation timeline.

---

## 7. Process Execution Evidence

The renamed executable was executed using:

```powershell
Start-Process "C:\System32MasqueradingLab\Payload\svchost.exe"
```

Sysmon Event ID 1 was subsequently observed:

```text
Event ID:
1

Time:
11-09-2026 08:20:29
```

This confirmed that the masquerading-style artifact was executed rather than simply stored on disk.

---

## 8. Process Investigation

A basic process-name query was initially performed:

```powershell
Get-Process svchost
```

Multiple `svchost.exe` processes were returned.

This was expected because Windows normally runs many Service Host processes.

The result demonstrated an important SOC investigation limitation:

```text
Process name alone is not enough.
```

A targeted query was therefore used to search for processes executing from the lab directory.

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.ExecutablePath -like "*System32MasqueradingLab*"
    } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

The resulting evidence was exported to:

```text
C:\System32MasqueradingLab\Evidence\process-evidence.txt
```

---

## 9. Wazuh Evidence

Wazuh correlated the process execution.

Important fields included:

```text
Timestamp:
Sep 11, 2026 @ 08:20:30.158

Agent:
001

Agent Name:
DESKTOP-9MMM37V

Image:
C:\System32MasqueradingLab\Payload\svchost.exe

Command Line:
C:\System32MasqueradingLab\Payload\svchost.exe

Current Directory:
C:\Windows\System32\

Description:
Notepad

Company:
Microsoft Corporation

File Version:
10.0.26100.9278 (WinBuild.160101.0800)

Integrity Level:
High
```

The most important correlation was:

```text
Filename:
svchost.exe

Path:
C:\System32MasqueradingLab\Payload\

Description:
Notepad

SHA256:
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The filename and binary metadata clearly disagreed.

---

## 10. Evidence Correlation

| Investigation Question | Evidence | Result |
|---|---|---|
| Is the filename trusted-looking? | `svchost.exe` | Yes |
| Is the path normal? | Lab directory | No |
| Does the hash match legitimate svchost? | Different SHA256 | No |
| What binary does the hash match? | `notepad.exe` | Notepad |
| Was the file created? | Sysmon Event ID 11 | Yes |
| Was the file executed? | Sysmon Event ID 1 | Yes |
| Does Wazuh identify the binary as Notepad? | Description: `Notepad` | Yes |
| Is the file digitally signed? | Authenticode | Yes |
| Is the activity malicious? | Controlled lab | No |

---

