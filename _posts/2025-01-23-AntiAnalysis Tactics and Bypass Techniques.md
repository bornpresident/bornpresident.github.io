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
>Note: Use Disassember :)
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
>Note: Use Dissambler and then Debbuger 
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
Updating.....
