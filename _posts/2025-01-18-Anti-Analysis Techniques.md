---
title: Anti-Analysis Techniques
author: Vishal Chand
date: 2024-11-18
categories:
  - Malware Analysis
tags:
  - Anti-Analysis Techniques
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/3.png
---

## Table of Contents
1. Types of Anti-Analysis Approaches
2. Avoid Being Analyzed by Tools Approach
   2.1. Debugger Detection
   2.2. Virtualization Detection
   2.3. Analysis Tools Detection
3. Avoid Being Analyzed by Analyst Approach
   3.1. TLS Callback
   3.2. Junk Code Insertions
   3.3. Code Transportation
   3.4. Proxy Function
   3.5. Anti-Disassembler

## 1. Types of Anti-Analysis Approaches

### 1.1. To avoid being analyzed by tools
- Depending on detecting analysis tools and avoiding execution under these tools

### 1.2. To avoid being analyzed by analyst  
- Depending on adding multiple layers of complexity to make analysis process more difficult
- Confuse analyst by adding non-related codes and intersected execution flow

## 2. Avoid Analysis by Tools Approach

### 2.1. Debugger Detection
#### 2.1.1. Detection Methods Overview
- Detection by flags
- Detection by parent process
- Detection by execution timing  
- Detection by breakpoints

#### 2.1.2. Detection by Flags
##### 2.1.2.1. BeingDebugged
- The simplest way to detect debugger
- Could be done using Windows APIs:
  - IsDebuggerPresent
  - CheckRemoteDebuggerPresent
- Could be done manually by checking BeingDebugged flag in PEB:
```asm
mov eax, dword ptr fs:[30h] ; PEB
cmp byte ptr [eax+2], 1 ; PEB.BeingDebugged
jz <debugged>
```

##### 2.1.2.2. NtGlobalFlag
- Exists in PEB at offset 0x68 in 32-bit systems and 0xBC in 64-bit systems
- In normal execution its value is zero
- Under debugger its value is 0x70:
  - FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
  - FLG_HEAP_ENABLE_FREE_CHECK (0x20)
  - FLG_HEAP_VALIDATE_PARAMETERS (0x40)

Example assembly code:
```shell
mov eax, large fs:30h        ; PEB struct loaded into EAX
mov eax, [eax+68h]          ; NtGlobalFlag saved to EAX
sub eax, 70h                ; Compare with debug flags
mov [ebp+var_1828], eax
cmp [ebp+var_1828], 0       ; Check debug flags
jnz short loc_4035B5        ; No debugger, continue
call s_selfDelete           ; Debugger detected, delete self
```

#### 2.1.3. Detection by Parent Process
- In normal execution, process of malware should be a child process of the process of infection vector (browser, mail client, etc)
- While debugging, the parent process will be the debugger process
- Malware could check its parent process to detect debugger
- This technique done by getting parent process ID then getting parent process name or parent process file name

##### 2.1.3.1. Detection Methods
- Using CreateToolhelp32Snapshot, Process32First and Process32Next Windows APIs to loop all running processes
- Using undocumented NtQueryInformationProcess API to get parent process ID, then GetProcessImageFileNameA for file name
- Need PROCESS_QUERY_INFORMATION permission through OpenProcess API

#### 2.1.4. Detection by Execution Timing
- This technique depends on the difference between machine speed and human speed
- Malware uses rdtsc instruction to get system time in sequence then calculate difference between two results which should be in range of milliseconds

##### 2.1.4.1. Alternative APIs
- GetLocalTime
- GetSystemTime 
- GetTickCount
- QueryPerformanceCounter
- timeGetTime
- timeGetSystemTime

Example timing check code:
```shell
RDTSC                           ;get time 1st value
PUSH EAX                       ;save 1st value in stack 
XOR EAX, EAX
RDTSC                          ;get time 2nd value
SUB EAX, dword ptr [ESP]      ;calculate difference
CMP EAX, 0x20                 ;check if > 20ms
JA Debugger_Detected
```

#### 2.1.5. Detection by Break Points
- Single-stepping is the basic concept of break points
- Trap flag is a flag in FLAGS register that interrupts execution after each instruction
- Detecting trap flag means malware is being debugged
- Detecting trap flag is very hard because:
  - FLAGS register is not readable like other registers
  - Trap flag is always cleared after returning execution to debugger

##### 2.1.5.1. Hardware Breakpoint Detection
- Hardware breakpoints stored in DR0-DR3
- Main detection is via Thread Context
- Two common detection methods:
  - Using SEH (Structured Exception Handling) with exception callback
  - Using Windows APIs: GetThreadContext and SetThreadContext

##### 2.1.5.2. Software Breakpoint Detection
- Software breakpoints are code patching
- Detection methods:
  - Searching code for 0xcc (INT3)
  - Calculate checksum of code and compare with precalculated value
  - Read code section from malware file and compare with memory version

### 2.2. Virtualization Detection

#### 2.2.1. Detection Methods Overview
- Detection by Processes
- Detection by WMI
- Detection by Registry  
- Detection by MMX Registers

#### 2.2.2. Detection by Processes
- Virtual machines run specific processes for enhanced functionality
- Detecting these processes reveals VM environment
- Use CreateToolhelp32Snapshot APIs to scan for:
  - vmtoolsd.exe
  - vmacthlp.exe
  - VMwareUser.exe
  - VMwareService.exe
  - VMwareTray.exe
  - VBoxService.exe
  - VBoxTray.exe

#### 2.2.3. Detection by WMI
- Can query system info through PowerShell Get-WmiObject
- WMI queries to detect VMs:
```sql
SELECT * FROM Win32_ComputerSystem WHERE Manufacturer LIKE "%VMware%" AND Model LIKE "%VMware Virtual Platform%"

SELECT * FROM Win32_ComputerSystem WHERE Manufacturer LIKE "%Microsoft Corporation%" AND Model LIKE "%Virtual Machine%"
```

#### 2.2.4. Detection by Registry
Common registry keys to check:
```
HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0
HKLM\SOFTWARE\VMware, Inc.\VMware Tools
HKLM\HARDWARE\ACPI\DSDT\VBOX__
HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
```

#### 2.2.5. Detection by MMX Registers
- MMX registers were introduced by Intel for graphics calculations
- Some virtualization tools don't support them
- Malware can test MMX presence to detect VMs

### 2.3. Analysis Tools Detection

#### 2.3.1. Detection Methods Overview
- Detection by Name
- Detection by Window Attributes
- SandBox Detection

#### 2.3.2. Tools Detection by Name
- Use CreateToolhelp32Snapshot APIs to scan processes
- On detection, malware can:
  - Terminate itself
  - Terminate the matched process using TerminateProcess API

#### 2.3.3. Tools Detection by Window Attributes
- Some analysts rename analysis tools to avoid detection
- Malware can search for window names/classes instead
- Window names are more descriptive than process names
- Detection methods:
  - FindWindow API with known tool names
  - EnumWindows with GetWindowText API

#### 2.3.4. SandBox Detection
Methods include:
- Detecting human behavior (mouse movements)
- Checking for sandbox-related DLLs:
  - api_log.dll
  - dir_watch.dll
  - sbiedll.dll
- Delaying execution since sandboxes run for limited time

## 3. Anti-Disassembler Techniques
- Techniques designed to frustrate disassembly process
- Prevents finding correct instruction starting addresses
- Results in failed or incorrect disassembly listings