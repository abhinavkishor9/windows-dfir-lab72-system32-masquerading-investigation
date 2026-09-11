# Troubleshooting Notes 

## 1. Multiple svchost.exe Processes Were Returned

### Observation

Running:

```powershell
Get-Process svchost
```

returned multiple `svchost.exe` processes.

### Explanation

This is normal Windows behavior.

The legitimate Service Host process is commonly used by multiple Windows services, so several `svchost.exe` instances can exist simultaneously.

### Investigation Improvement

Do not rely only on:

```powershell
Get-Process svchost
```

Instead, inspect executable paths:

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "svchost.exe"
    } |
    Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine
```

For the lab specifically:

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.ExecutablePath -like "*System32MasqueradingLab*"
    } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

---

## 2. The Lab Process May Not Appear in a Process Query

### Observation

The simple process-name query did not clearly distinguish the lab executable from the many legitimate `svchost.exe` processes.

### Possible Reason

The controlled Notepad binary may terminate quickly after execution, depending on how it was launched and interacted with.

A process query performed after the process has exited will not show the process.

### Recommended Approach

Use Sysmon Event ID 1 as the historical execution source:

```text
Sysmon Event ID 1
        ↓
Process Create
        ↓
Image
CommandLine
ParentImage
User
Hashes
```

This is more reliable for retrospective investigation than checking only currently running processes.

---

## 3. Use the Executable Path Instead of the Filename

### Problem

A query based only on:

```text
svchost.exe
```

can return many legitimate processes.

### Better Investigation

Search for the full executable path:

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

PowerShell:

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.ExecutablePath -eq "C:\System32MasqueradingLab\Payload\svchost.exe"
    } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

The path provides significantly more context than the process name.

---

## 4. Sysmon Event 11 Was Used for File Creation

### Event

The artifact generated:

```text
Event ID: 11
Time: 11-09-2026 07:41:12
```

### File

```text
C:\System32MasqueradingLab\Payload\svchost.exe
```

### Investigation Value

Event ID 11 establishes that the suspicious-looking executable was created on disk.

It does not by itself prove that the file was executed.

Execution was confirmed separately using Sysmon Event ID 1.

---

## 5. Sysmon Event 1 Was Used for Execution

### Event

```text
Event ID: 1
Time: 11-09-2026 08:20:29
```

### Investigation Value

Event ID 1 provided process-creation telemetry.

The key field was:

```text
Image:
C:\System32MasqueradingLab\Payload\svchost.exe
```

This connected the trusted-looking filename with its unexpected execution path.

---

## 6. Wazuh Event May Arrive Slightly After Sysmon

### Observation

Sysmon recorded process creation at:

```text
08:20:29
```

Wazuh recorded the corresponding event at:

```text
Sep 11, 2026 @ 08:20:30.158
```

### Explanation

A small delay is expected because telemetry must travel through the endpoint collection and Wazuh processing pipeline.

The approximately one-second difference does not indicate a separate execution.

### Investigation Approach

Correlate:

```text
Host
+
Executable Path
+
Command Line
+
Event Type
+
Timestamp
```

rather than requiring timestamps to match exactly.

---

## 7. Valid Digital Signature Did Not Make the Execution Legitimate

### Observation

The executable had a valid Microsoft signature.

### Potential Misinterpretation

A valid signature could incorrectly lead to:

```text
"Microsoft signed = safe"
```

### Correct Interpretation

The signature establishes the authenticity of the underlying binary.

It does not establish that:

- The filename is appropriate.
- The file is in the correct directory.
- The execution is expected.
- The user intended the execution.
- The process behavior is benign.

In this lab:

```text
Valid signature
+
Unexpected filename
+
Unexpected path
+
Execution
=
Requires investigation
```

---

## 8. Filename and Metadata Did Not Match

### Observation

Wazuh reported:

```text
Image:
C:\System32MasqueradingLab\Payload\svchost.exe
```

but also reported:

```text
Description:
Notepad
```

### Explanation

The file had been renamed from `notepad.exe` to `svchost.exe`.

The internal executable metadata therefore continued to identify the binary as Notepad.

### Investigation Value

This is a strong example of why filename-based trust is unreliable.

---

## 9. Hash Comparison Resolved the Binary Identity

The legitimate `svchost.exe` hash was:

```text
1222A44A5FDB4EFDE4DFCB41093648627950E7EC02D8667F1C26CCAE31D922E2
```

The lab artifact hash was:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The lab hash matched the original Notepad binary.

Therefore:

```text
Filename:
svchost.exe

Actual binary:
notepad.exe
```

---

## 10. Do Not Modify Real System32 Files

The lab intentionally avoided replacing or editing:

```text
C:\Windows\System32\svchost.exe
```

Instead, a copy of:

```text
C:\Windows\System32\notepad.exe
```

was placed in:

```text
C:\System32MasqueradingLab\Payload\
```

and renamed.

This approach reproduces the investigation condition without modifying a protected Windows system binary.

---

## 11. Evidence Export

Evidence was stored under:

```text
C:\System32MasqueradingLab\Evidence\
```

Files:

```text
process-evidence.txt
file-metadata.txt
hash.txt
signature.txt
```

Keeping these artifacts separate from the payload helps maintain a clean investigation structure.

---
