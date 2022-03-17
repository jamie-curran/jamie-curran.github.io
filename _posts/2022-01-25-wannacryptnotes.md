---  
layout: post  
title:  "wannacryptnotes"  
date:   2022-01-25 16:16:01 -0600  
categories: jekyll update  
---

# Introduction 
This will be an on going post todo with reverse engineering wannacry(pt) in my free time, as well as testing out newer reverse engineering skills that I gain over time.
By the end of this, I would like to extract the eternal blue exploit, how the code handles c2 commands and lastly the encryption methodology.

I gathered this sample from the zoo, link github, I will be making other blog posts on other malware from their collection.

# Initial workings

## Strings
Running strings from the sample, we gain some legable information.
```xml

<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
        <assemblyIdentity
            type="win32"
            name="Microsoft.Windows.Common-Controls"
            version="6.0.0.0"
            processorArchitecture="*"
            publicKeyToken="6595b64144ccf1df"
            language="*"
        />
    </dependentAssembly>
  </dependency>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application> 
       <!-- Windows 10 --> 
       <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
       <!-- Windows 8.1 -->
       <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
       <!-- Windows Vista -->
       <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/> 
       <!-- Windows 7 -->
       <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
       <!-- Windows 8 -->
       <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
    </application> 
  </compatibility>
</assembly>
PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING

```

The xml is auto generated compile information specfic to windows, and provides some sense of the orignal programming lanauge used.

Further information extracted from the strings:
```
Microsoft Enhanced RSA and AES Cryptographic Provider
CryptGenKey
CryptDecrypt
CryptEncrypt
CryptDestroyKey
CryptImportKey
CryptAcquireContextA
cmd.exe /c "%s"
115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn
12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
%s%d
Global\MsWinZonesCacheCounterMutexA
tasksche.exe
TaskStart
t.wnry
icacls . /grant Everyone:F /T /C /Q
attrib +h .
WNcry@2ol7
GetNativeSystemInfo
.?AVexception@@
incompatible version
buffer error
insufficient memory
data error
stream error
file error
stream end
need dictionary
invalid distance code
invalid literal/length code
invalid bit length repeat
too many length or distance symbols
invalid stored block lengths
invalid block type
incomplete dynamic bit lengths tree
oversubscribed dynamic bit lengths tree
incomplete literal/length tree
oversubscribed literal/length tree
empty distance tree with lengths
incomplete distance tree
oversubscribed distance tree
1.1.3
incorrect data check
incorrect header check
invalid window size
unknown compression method
```
The command:
> cmd.exe /c "%s"
115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn
12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94


Seems interesting but the broken lines makes it harder to decode. some reverse engineering might provide clarity.

## static analysis, ghidra: 

### entry function
```c
  SetCurrentDirectoryA(&local_210);
  FUN_004010fd(1);
  FUN_00401dab((HMODULE)0x0);
  FUN_00401e9e();
  FUN_00401064(s_attrib_+h_._0040f520,0,(LPDWORD)0x0);
  FUN_00401064(s_icacls_._/grant_Everyone:F_/T_/C_0040f4fc,0,(LPDWORD)0x0);
  iVar7 = FUN_0040170a();
  if (iVar7 != 0) {
    FUN_004012fd();
    iVar7 = FUN_00401437(local_6e8,(LPCSTR)0x0,0,0);
    if (iVar7 != 0) {
      local_8 = 0;
      psVar5 = (short *)FUN_004014a6(local_6e8,s_t.wnry_0040f4f4,&local_8);
      if (((psVar5 != (short *)0x0) &&
          (piVar2 = (int *)FUN_004021bd(psVar5,local_8), piVar2 != (int *)0x0)) &&
         (pcVar6 = (code *)FUN_00402924(piVar2,s_TaskStart_0040f4e8), pcVar6 != (code *)0x0)) {
        (*pcVar6)(0,0);
      }
    }
    FUN_0040137a();
```
of note:
> s_TaskStart_0040f4e8

and
> FUN_00401064(s_icacls_._/grant_Everyone:F_/T_/C_0040f4fc,0,(LPDWORD)0x0);

Seems to be a privesc runctions.

I will need to deobscure this file and find the earlier string.


## Live analysis

## wireshark 

Nothing came out of the windows machine, most likely due to windows alerting that the network was disabled.




---

Possible solutions:
- set up network and only allow windows to pass their checks?
- physical firewall rules and monitoring, allowing for shutoff whenever theres an unknown domain call/unapproved.
- dump the ram and perform forensics.
Possible further issues:
- safely extract information from the sandboxed enviroment
	- dmz box?
	- sandboxed only reverse engineering
	- usb but wipe it after every use

- creditals on box need to be throwaway, but ms forces login to ms account past 11.



---

# UPDATE: 2022-03-13

After some further reading and expermentation during a ctf (blog post soon), I will be doing the following to further analyse the sample:
- Check for unpacking (DIE)
- If there is unpacking, extract and ghidra that sample.
- Live reverse engineer within linux? (wine with r2? wine-dbg?), further reading into these tools.


