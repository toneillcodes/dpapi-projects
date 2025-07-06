# dpapi-projects
This is a collection of research materials and offensive tools for the Windows DPAPI architecture.  
The goal is to deepen my own understanding and share whatever I can along the way.

## What is DPAPI?
Data Protection Application Programming Interface is a set of APIs used to protect and unprotect secrets on a Windows system.  
This functionality allows developers to obfuscate secure application data without implementing cryptography algorithms.  
Check out my posts on medium:
-  [Windows DPAPI Fundamentals](https://medium.com/@toneillcodes/windows-dpapi-fundamentals-69af5169ffe8)
-  [DPAPI Blob Hunting](https://medium.com/@toneillcodes/dpapi-blob-hunting-967d2baead6a): Be vewy, vewy quiet, I’m hunting secrets
-  [Reading DPAPI Protected Blobs](https://medium.com/@toneillcodes/decoding-dpapi-blobs-1ed9b4832cf6): Making opaque blobs less opaque
-  [Extracting DPAPI MasterKey Data](https://medium.com/@toneillcodes/extracting-dpapi-masterkey-data-1381168ad5b8): An analysis of the DPAPI MasterKey binary structure and a PoC tool to extract key data
-  [Decrypting DPAPI Credentials Offline](https://medium.com/@toneillcodes/decrypting-dpapi-credentials-offline-8c8f27207956): An OPSEC-conscious approach to decrypting DPAPI Credentials
-  [Using Living off the Land Techniques to Extract DPAPI Credentials](https://TBD): Fileless DPAPI credential extraction with PowerShell

## Project List
- [DPAPIDataExample](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIDataExample): C# project demonstrating the use of the ProtectedData class to protect/unprotect data stored in file
- [DPAPIBlobHunter](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIBlobHunter): C# project demonstrating methods of scanning the filesystem and registry for DPAPI blobs
- [DPAPIBlobReader](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIBlobReader): C# project demonstrating the processing of a DPAPI protected blob
- [DPAPIMasterKeyReader](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIMasterKeyReader): C# project demonstrating the processing of a DPAPI master key file
- [DPAPIPowerShell](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIPowerShell): PowerShell snippets related to DPAPI
- [PowerDPAPI](https://github.com/toneillcodes/dpapi-projects/tree/main/PowerDPAPI): PowerShell project to locate, parse and dump DPAPI credential blobs and the corresponding master key
