# dpapi-projects
## What is DPAPI?
.NET provides access to the data protection API (DPAPI), which allows you to encrypt data using information from 
the current user account or computer. When you use the DPAPI, you alleviate the difficult problem of explicitly 
generating and storing a cryptographic key.  
Source: [Microsoft: How to Use Data Protection](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

- [ProtectedData](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=netframework-4.8.1) Provides methods for encrypting and decrypting data.
- [ProtectedMemory](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protectedmemory?view=netframework-4.8.1) Provides methods for protecting and unprotecting memory.

The classes consist of two wrappers for the unmanaged DPAPI: Protect and Unprotect.  
These two methods can be used to encrypt and decrypt data such as passwords, keys, and connection strings.

## ProtectedData Methods
```
public static byte[] Protect(byte[] userData, byte[] optionalEntropy, System.Security.Cryptography.DataProtectionScope scope);  
public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, System.Security.Cryptography.DataProtectionScope scope);
```

## ProtectedMemory Methods
```
public static void Protect(byte[] userData, System.Security.Cryptography.MemoryProtectionScope scope);  
public static void Unprotect(byte[] encryptedData, System.Security.Cryptography.MemoryProtectionScope scope);
```
