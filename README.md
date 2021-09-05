# IAT-Obfuscation

This Project is for IAT Obfuscation to make static analysis of a program harder, and to make it harder for recognize and extract the sequence of API for malicious activity staticly.

# How To Use:
```
1- Include the TLS.h header file in your project then compile it (this will add TLS section in the executable that will fix IAT before your main function)
2- execute IAT-Obfuscation.exe <Executable from step 1> <Output File Name>
```

# How it work
this obfuscation technique work by replacing every two api in the same DLL with each other 

![](https://github.com/MahmoudZohdy/IAT-Obfuscation/blob/main/images/IAT-Obfuscation.PNG)

# Demo 

this is the output of simple injection technique to Load Dll in Remote Process (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)

UnObfuscated Version
![Clean](https://github.com/MahmoudZohdy/IAT-Obfuscation/blob/main/images/UnObfuscatedInjection.PNG)

Obfuscated Version
![Obfuscated](https://github.com/MahmoudZohdy/IAT-Obfuscation/blob/main/images/ObfuscatedInjection.PNG)
