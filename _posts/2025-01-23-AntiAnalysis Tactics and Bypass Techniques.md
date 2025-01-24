---
title: MacOS Malware:Anti-Analysis Tactics and Bypass Techniques
author: Vishal Chand
date: 2025-01-23
categories: [Malware Analysis]
tags: [MacOS,Anti-Analysis]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/15.png
---

Understanding binary analysis is crucial for malware researchers. When you have access to binary files, you'll be equipped to dissect and analyze malicious code effectively. Let's dive in!

Common Anti-Static Anlysis Approaches 
1. String based obfsucation/encryption.
2. Code obfsucation.

## String based obfuscation methods & bypass
### 1. Sensitive Strings Disgusied as Constants 
Note: Use Disassember :)

Sentive strings are splited into chunks,because of chunk size `strings` command may miss those sensitve data.
Solution ? Instruct the disassembler to decode the constants as characters instead of the default, hexadecimal. In the Hopper disassembler, you can simply `CTRL-click` the constant and select Characters to use the `SHIFT-R` keyboard shortcut 

```shell
#Before 
main:
...
0x000000010000b5fa movabs rcx, 0x7473696c702e74
0x000000010000b604 mov qword [rbp+rax+var_209], rcx
0x000000010000b60c movabs rcx, 0x746e6567612e706f
0x000000010000b616 mov qword [rbp+rax+var_210], rcx
0x000000010000b61e movabs rcx, 0x6f6c2d7865612e6d
0x000000010000b628 mov qword [rbp+rax+var_218], rcx
0x000000010000b630 movabs rcx, 0x6f632f73746e6567
0x000000010000b63a mov qword [rbp+rax+var_220], rcx
0x000000010000b642 movabs rcx, 0x4168636e75614c2f
0x000000010000b64c mov qword [rbp+rax+var_228], rcx
0x000000010000b654 movabs rcx, 0x7972617262694c2f
0x000000010000b65e mov qword [rbp+rax+var_230], rcx

#After 

main:
...
0x000000010000b5fa movabs rcx, 't.plist'
0x000000010000b604 mov qword [rbp+rax+var_209], rcx
0x000000010000b60c movabs rcx, 'op.agent'
0x000000010000b616 mov qword [rbp+rax+var_210], rcx
0x000000010000b61e movabs rcx, 'm.aex-lo'
0x000000010000b628 mov qword [rbp+rax+var_218], rcx
0x000000010000b630 movabs rcx, 'gents/co'
0x000000010000b63a mov qword [rbp+rax+var_220], rcx
0x000000010000b642 movabs rcx, '/LaunchA'
0x000000010000b64c mov qword [rbp+rax+var_228], rcx
0x000000010000b654 movabs rcx, '/Library'
0x000000010000b65e mov qword [rbp+rax+var_230], rcx

```
### 2. Encrpted Strings 
`Note: Use Dissambler and then Debbuger`
1. You can use Network mointor which can help us passively recover the address of malware's C2.Same can be achieved by debugger
2. You could also set a breakpoint on the return instruction (retn) within the decryption function. When the breakpoint is hit you’ll once again find the decrypted string in the RAX register.
3. A more efficient approach would be to add additional debugger commands (via breakpoint command add) to the breakpoint. Then, once the breakpoint is hit, your breakpoint commands will be automatically executed and could just print out the register holding the decrypted string and then allow the process to automatically continue. If you’re interested in the caller, perhaps to locate where a specific decrypted string is used, consider printing out the stack backtrace as well.

### 3. Locating Obfuscated Strings 
No foolproof method! But dissembler may reveal many chunks of obfsucated or high entropy data that are cross-refrenced else where in the binay code. Find function which is reasonable reposnisble.So you can set a breakpoint after code that references the encrypted data and then dump the decrypted data and then we can examine the decrypted data in memory. As it decrypts to a sequence of printable strings, we can display it via the x/s debugger command.

```shell
% lldb Finder.app

(lldb) process launch --stop-at-entry
(lldb) b 0x00007408
Breakpoint 1: where = Finder`Finder[0x00007408], address = 0x00007408

(lldb) c
Process 1130 resuming
Process 1130 stopped * thread #1, queue = 'com.apple.main-thread', stop reason
= breakpoint 1.1

(lldb) x/20s 0x0000e2f0
1 0x0000e2f8: "89.34.111.113:443;"
0x0000e4f8: "Password"
0x0000e52a: "HostId-%Rand%"
0x0000e53b: "Default Group"
0x0000e549: "NC"
0x0000e54c: "-"
2 0x0000e555: "%home%/.defaults/Finder"
0x0000e5d6: "com.mac.host"
0x0000e607: "{0Q44F73L-1XD5-6N1H-53K4-I28DQ30QB8Q1}"
...
```
### 4. Finding the Deobfucation code 
1. Use a disassembler or decompiler to identify code that references the encrypted data. These references generally indicate either the code responsible for ecryption or code that later references the data in a decrypted state.
2. Locating decryption routines is to peruse the disassembly for calls into system crypto routines (like CCCrypt) and well-known
crypto constants (such as AES’s s-boxes). In certain disassemblers, third-party plug-ins such as FindCrypt can automate this crypto discovery process.

> Drawback of breakpoint-based approach: It only allows you to recover specific decrypted strings. If an encrypted string is exclusively referenced in a block of code that isn’t executed, you’ll never encounter its decrypted value. 
{: .prompt-info }

So below is the more Comprehensive approach.

### 5. String Deobfuscation via a Hopper Script 

A more comprehensive approach is to re-implement the malware’s decryption routine and then pass in all the malware’s encrypted
strings to recover their plaintext values.

Thing is such disassemblers also generally support external third-party scripts or plug-ins that can directly interact
with a binary’s disassembly.So we create a Python-based Hopper script capable of decrypting all the embedded strings
in a sophisticated malware sample.

### 6. Forcing the malware to execute it's decrption routine

>  Create a dynamic library and inject it into the malware, this library can then directly invoke the malware’s string decryp-
tion routine for all encrypted strings, all without having to understand the internals of the decryption algorithm. 
{: .prompt-tip }

For that :

1. By using diassembely finf malware's deobfuscation logic that  is function name. Let's take `ei_str` as example.
2. Now create custom injectable libary that should do tasl. First irst, within a running instance of the malware, it will esolve the address of the deobfuscation function, ei_str. Then it will invoke the ei_str function for all encrypted strings found embedded within the malware’s binary. Because we place this logic in the constructor of the dynamic library, it will be
executed when the library is loaded, well before the malware’s own code is run.

```shell
//library constructor
//1. resolves address of malware's `ei_str` function
//2. invokes it for all embedded encrypted strings
__attribute__((constructor)) static void decrypt() {
  //define & resolve the malware's ei_str function
  typedef char* (*ei_str)(char* str);
  ei_str ei_strFP = dlsym(RTLD_MAIN_ONLY, "ei_str");
  //init pointers
  //the __cstring segment starts 0xF98D after ei_str and is 0x29E9 long
  char* start = (char*)ei_strFP + 0xF98D;
  char* end = start + 0x29E9;
  char* current = start;
  //decrypt all strings
  while(current < end) {
  //decrypt and print out
  char* string = ei_strFP(current);
  printf("decrypted string (%#lx): %s\n", (unsigned long)current, string);
  //skip to next string
  current += strlen(current);
  }
  //bye!
  exit(0);
}
```
So how it will be working? 

he library code scans over the malware’s entire __cstring segment,which contains all the obfuscated strings. For each string, it invokes the malware’s own ei_str function to deobfuscate the string. Once it’s compiled `(% clang decryptor.m -dynamiclib -framework Foundation -o decryptor.dylib)`, we can coerce the malware to load our decryptor library via the `DYLD_INSERT_LIBRARIES` environment variable by following command:

```shell
% DYLD_INSERT_LIBRARIES=<path to dylib> <path to Malwaret>
```
>  If the malware is compiled with a hardened runtime, the dynamic loader will ignore the DYLD_INSERT_LIBRARIES variable and fail to load our deobfuscator. To bypass this protection, you can first disable System Integrity Protection (SIP) and then execute command.
{: .prompt-warning }

```shell
#command
nvram boot-args="amfi_get_out_of_my_way=0x1
```
## Code-level Obfuscation 

Malware author adds `spurious`or `garbage` at compile time. These instructions are Non-operations. 

### Bypassing Packed Binary Code 
Packer is used which compresses binary code to prevent static anlysis while also inserting a small unpacker stub at the entry point of the bianry. The well known packer is UPX.
```shell
upx -d <MALWARE>
```
Example:
```shell
% upx -d ColdRoot.app/Contents/MacOS/com.apple.audio.driver
                Ultimate Packer for eXecutables
                    Copyright (C) 1996 - 2013
With LZMA support, Compiled by Mounir IDRASSI (mounir@idrix.fr)
File size                 Ratio           Format                   Name
--------------------      ------        ----------- -     ---------------------
3292828 <- 983040         29.85%        Mach/i386         com.apple.audio.driver

Unpacked 1 file.
```
#### Methods to know binary is packed or not:
1. Much higher level of randomness than normal binary instuctions.
2. Leverage `string` command.
3. Load the binary in your disassembly and persue the code and you may observe the following:
- Unsual section names. You can use `Mach-O viewer` tool. Eg- UPX adds a section named `_XHDR`.
- A majority of strings obfsucated/
- Large chunks of executable code that can't be diassembled.
- A low number of imports (references to external API)

> To get binary unpack run the packed sample under the watchful eye of a debugger, and once the unpacker stub has executed, dump the unprotected binary from memory
with the memory read LLDB command.
{: .prompt-tip }

### Decrypting encrypted Binaries
To automatically decrypt the malware at runtime, the encryptor will often insert a decryptor stub and keying information at the start of the binary unless the operating system natively.Anti-Analysis 203
supports encrypted binaries, which macOS does.

To recover the malware’s unencrypted instructions is to dump the unprotected binary code from memory once the decryption code has executed. For this specific malware specimen, its unencrypted code
can be found from address 0x7000 to 0xbffff. The following debugger command will save its unencrypted code to disk for static analysis:

```shell
lldb) memory read --binary --outfile /tmp/dumped.bin 0x7000 0xbffff --force
```
## Anti-dynamic Analysis Approaches

Malware author uses common approaches such as `Virtual Machine detection` & `Analysis tool detection`

See if you are using debugger it may prematurely exits. So the first goal is finf the code which is reposnisble(For this use static Analysis) and after that you can bypass the code by patching it out or skipping it in debugger session.

## How malware detect it's VM or debugger? 

### Checking the system MAC 

How? The malware invokes the system API to execute it. If the API returns a nonzero value, the malware will prematurely exit.
```shell
rax = decodeString(&encodedString);
if (system(rax) != 0x0) goto leave;

leave:
  rax = exit(0xffffffffffffffff);
  return rax;
}
```
System name can be known bu `hw.model`. So, In VM, this command will return a nonzero,as the value for `hw.model` will not contain `Mac`.

```shell
#When it's VM 
% sysctl hw.model
hw.model: VMware<Version>

# When it's MAC 
% sysctl hw.model
hw.model: MacBookAir7,2
```
### Counting the system's Logical & Physical CPUs 
How? By executing the following command:
```shell
echo $((`sysctl -n hw.logicalcpu`/`sysctl -n hw.physicalcpu`))|grep 2 > /dev/null
```
> The malware checks the ratio of logical to physical CPUs. On virtual machines, this value is often 1. If it’s not 2, the malware exits. On native hardware, the ratio is typically 2, allowing the malware to proceed.
{: .prompt-warning }

### Checking the system's MAC address 
By checkingorganizationally unique identifier (OUI). If MAC address = OUI of any VM then it will exit.

### Checking System Integrity Protection Status
If SIP is disabled,then malware exits. Why? Because malware analysts, who often require the ability to debug any and all processes, will often disable
SIP on their analysis machines. 

Malware author will execute macOS’s `csrutil` command to determine the status of SIP. 
```shell
(lldb) po [$rdi launchPath]
/bin/sh.

(lldb) po [$rdi arguments]
<__NSArrayI 0x10580dfd0>(
-c,
  command -v csrutil > /dev/null && csrutil status |
  grep -v "enabled" > /dev/null && echo 1 || echo 0
)
``` 
### Detecting or Killing Specific Tools

### Detecting debugger
> Apple’s developer documentation, a process should first invoke the sysctl API with CTL_KERN, KERN_PROC, KERN_PROC_PID, and its process identifier (pid), as parameters. Also, a kinfo_proc structure should be provided.14
The sysctl function will then populate the structure with information about the process, including a P_TRACED flag. If set, this flag means the process is currently being debugged
{: .prompt-tip}

###### Preventing Debugging with `ptrace`
Malware can accomplish this by invoking the `ptrace` system call with the `PT_DENY_ATTACH` flag. This Apple-specific flag prevents a debugger from attaching and tracing the malware. Attempting to debug a process that
invokes ptrace with the PT_DENY_ATTACH flag will fail.

```shell
% lldb proton
...
(lldb) r
Process 666 exited with status = 45 (0x0000002d)
```
> You can tell the malware has the PT_DENY_ATTACH flag set because it prematurely exits with a status of 45.Calls to the ptrace function with the `PT_DENY_ATTACH` flag are fairly easy
to spot (for example, by examining the binary’s imports). 
{: .prompt-tip}

## Bypassing Anti-dynamic Analysis logic

2 STEPS!!!! IDENTIFY THE LOCATION OD ANTI-ANLYSIS LOGIC & THEN PREVENTING ITS EXECUTION.

Strings or function names, like **is_debugging** and **is_virtual_mchn**, may indicate the malware's aversion to analysis, by using **nm** command.

> If you step over a function and the malware immediately exits, it’s likely that some anti-analysis logic was triggered. If this occurs, simply restart the debugging session and step into the
function to examine the code more closely.
{: .prompt-tip}

A trial-and-error approach for analyzing malware can be summarized as:  

1. Start debugging the malicious sample from the very beginning to avoid triggering anti-analysis logic.  
2. Set breakpoints on APIs like **sysctl** and **ptrace** that may detect virtual machines or debugging.  
3. Step through the code manually, examining arguments if breakpoints are hit (e.g., **ptrace** with **PT_DENY_ATTACH**). Use backtraces to locate the triggering code.  
4. If the malware exits while stepping over a function, restart and step into the function to identify anti-analysis logic.  

Once located, bypass the anti-analysis mechanisms by altering the environment, patching the binary, modifying control flow, or adjusting values in the debugger.

## Let's bypass!

### 1. modifying the execution enviroment
Modify MAC address 

### 2. Patching the binary image 
In this we bypass anti-analysis logic by patching the malware's on-disk binary image. Example Mac malwaere `KeRanger` it sleep for serval days before executing payload. During satic analysis it was found that the function aptly named waitOrExit that is responsible for implementing the
wait delay. It is invoked by the startEncrypt function, which begins the process of ransoming users’ files.
```shell
startEncrypt:
...
214 Chapter 9
0x000000010000238b call waitOrExit
0x0000000100002390 test eax, eax
0x0000000100002392 je leave
```
To bypass the delay logic so that the malware will immediately continue execution, we can modify the malware’s binary code to skip the call to the waitOrExit function.
In a hex editor, we change the bytes of the malware’s executable instructions from a call to a nop. Short for “no operation,” a nop is an instruction (0x90 on Intel platforms) that instructs the CPU to do, well, nothing.

> Issues:
1. First, if the malware is packed with a non-UPX packer that is difficult to unpack.
2. On-disk patches involve more work than less permanent methods.
3. Any modification to a binary will invalidate any of its cryptographic signatures. 
{: .prompt-warning}

### 3. Modifying the malware's Instruction pointer 

Manipulating the program’s instruction pointer, which points to the next instruction that the CPU will execute. This value is stored in the program counter register, which on `64-bit` Intel systems is the `RIP` register. You can set a breakpoint on the
anti-analysis logic, and when the breakpoint is hit, modify the instruction pointer to, for example, skip over problematic logic.

You can change the value of any register via the reg write debugger command. 

```shell
(lldb) reg write $rip <new value>
```
> Manipulating the instruction pointer of a program can have serious side effects if not done correctly. For example, if a manipulation causes an unbalanced or misaligned stack, that program may crash. 
{: .prompt-warning}

### 4. Modifying a register Value 

We can set a breakpoint on the instruction that performs the check of the value returned by the is_debugging function. Once this breakpoint is hit, the `EAX register` will
contain a nonzero value, as the malware will have detected our debugger.However, via the debugger, we can surreptitiously toggle the value in EAX to 0

```shell
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
->  0x10000b89f: cmpl $0x0, %eax
    0x10000b8a2: je 0x10000b8b2
    0x10000b8a8: movl $0x1, %edi
    0x10000b8ad: callq exit

(lldb) reg read $eax
rax = 0x00000001

(lldb) reg write $eax 0
```
### 5. Enviromentally Generated Keys

Sophisticated malware authors employ protection encryption schemes that use environmentally generated keys. These keys are generated on the victim’s system and
are thus unique to a specific instance of an infection.

The only way to analyze the malware is either by performing the analysis directly on the infected system or by performing it on a memory dump of the malware captured on the infected system.