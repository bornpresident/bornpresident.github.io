---
title: Is This App Safe ?Guide to macOS Binary Verification
author: Vishal Chand
date: 2025-02-14
categories: [Malware Analysis]
tags: [MacOS, False positve]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/16.png
---
With macOS increasingly targeted by malware, verifying the authenticity and security of applications is more crucial than ever. Whether you're a cybersecurity researcher, malware analyst, or a macOS power user, this guide will equip you with practical techniques to ensure the integrity and security of macOS applications.

### 1. Check the Code signature 
Use the `codesign` command to verify the authenticity and integrity of the binary:

```shell
codesign -dv --verbose=4 /path/to/binary
```
### 2. Check if the Notarization Ticket Exists and is Stapled
Apple notarization ensures that the binary has been scanned for security issues. Verify notarization using:

```shell
spctl -a -vvv -t execute /path/to/binary
```
>What is a Stapled Notarization Ticket in macOS?
In macOS, stapling refers to embedding a notarization ticket inside an app bundle. This allows the app to be verified offline by Gatekeeper without requiring an internet connection.  
{: .prompt-info }

A notarized app may not necessarily have the notarization ticket stapled. To check:
```shell
stapler validate /path/to/App.app
```
Expected Output (If Stapled)
```shell
Processing: /path/to/App.app
The validate action worked!
```
If the ticket is not stapled, you’ll see:
```shell
Processing: /path/to/App.app
Error: ticket not found
```
What If an App is Notarized But Not Stapled?

1. The app can still run on macOS, but Gatekeeper will verify the notarization online.
2. If offline, macOS might flag it as untrusted.

To automate notarization and stapling verification:
```python
import subprocess

def check_notarization(app_path):
    result = subprocess.run(["spctl", "-a", "-t", "execute", "-vv", app_path], capture_output=True, text=True)
    if "source=Notarized Developer ID" in result.stdout:
        print(f"[+] {app_path} is notarized.")
    else:
        print(f"[!] {app_path} is NOT notarized.")

def check_stapled(app_path):
    result = subprocess.run(["stapler", "validate", app_path], capture_output=True, text=True)
    if "worked" in result.stdout:
        print(f"[+] {app_path} has a notarization ticket stapled.")
    else:
        print(f"[!] {app_path} does NOT have a stapled ticket.")

# Example usage
app_bundle = "/path/to/App.app"
check_notarization(app_bundle)
check_stapled(app_bundle)
```

### 3. Analyze the Binary’s Hash and Reputation
```shell
shasum -a 256 /path/to/binary
```
### 4. Check the Entire App Bundle for Suspicious Attributes
```shell
find /path/to/App.app -exec xattr -l {} +
```
### 5. Check the `dylibs` Used
```shell
otool -L /path/to/App.app/Contents/MacOS/executable
```
### 6. Check Load Commands
```shell
otool -l /path/to/App.app/Contents/MacOS/executable
```
Look for `LC_LOAD_DYLIB` and `LC_MAIN.`

### 7. Check Frameworks Used
```shell
find /path/to/App.app/Contents/Frameworks -type f -name "*.dylib"
```
### 8. Check Imports and Exports

```shell
nm -gU /path/to/App.app/Contents/MacOS/executable
```
### 9.  Run Dynamically and Observe Behavior

Tools:

1. `dtruss` – Trace system calls:

```shell
sudo dtruss -p $(pgrep AppName)
```
2. `fs_usage` – Monitor file system activity:

```shell
sudo fs_usage -w -f filesys
```
3. `sudo opensnoop` – Track file opens:

```shell
sudo opensnoop -n AppName
```
4. sudo lsof -p <PID> – Check open files:
```shell
sudo lsof -p $(pgrep AppName)
```
### 10. Check Logging (ES, Unified, Crash Logs, Sysdiagnose)
1. Endpoint Security (ES) logs:
Requires a custom agent using Apple's ES framework.

2. Unified Logging:
```bash
log stream --predicate 'processImagePath contains "AppName"'
```
3. Crash logs 
```bash
ls -lt ~/Library/Logs/DiagnosticReports/
```
4. Sysdiagnose:
```bash
sudo sysdiagnose -f ~/Desktop/
```
### 11. Check the Entitlements of the App Bundle or Executable
```bash
codesign -d --entitlements :- /path/to/App.app/Contents/MacOS/executable
```
Look for com.apple.security.automation.apple-events, com.apple.security.network.client, etc.