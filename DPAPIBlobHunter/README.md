# DPAPIBlobHunter
C# project demonstrating methods of scanning the filesystem and registry for DPAPI blobs<br>
Be sure to update the filesystem and registry search base values
```
static string searchPath = @"C:\Users\<username>\AppData\Local\Microsoft\Credentials";
static string registrySearchPath = "Software";
```
