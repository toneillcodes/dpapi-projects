# dpapi-projects
This is a collection of research materials and offensive tools for the Windows DPAPI architecture.  
None of this (so far) is new, but the goal is to deepen my own understanding and share whatever I can along the way.

## What is DPAPI?
Data Protection Application Programming Interface is a set of APIs used to protect and unprotect secrets on a Windows system.  
This functionality allows developers to obfuscate secure application data without implementing cryptography algorithms.  
Check out my posts on medium:
-  [Windows DPAPI Fundamentals](https://medium.com/@toneillcodes/windows-dpapi-fundamentals-69af5169ffe8)
-  [DPAPI Blob Hunting](https://medium.com/@toneillcodes/dpapi-blob-hunting-967d2baead6a)

## Project List
- [DPAPIDataExample](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIDataExample): C# project demonstrating the use of the ProtectedData class to protect/unprotect data stored in file
- [DPAPIBlobHunter](https://github.com/toneillcodes/dpapi-projects/tree/main/DPAPIBlobHunter): C# project demonstrating methods of scanning the filesystem and registry for DPAPI blobs
