public static class DPAPIMasterKeyReader
{
    static bool debugMode = false;
    static bool verboseMode = false;

    public static int Main(string[] args)
    {
        Console.WriteLine("[*] Running DPAPIMasterKeyReader.");

        string filename = "";
        if (args.Length >= 1)
        {
            filename = args[0];
            ParseMasterKey(filename);
        }
        else
        {
            Console.WriteLine("[ERROR] Filename required!");
            Console.WriteLine("Usage: DPAPIMasterKeyReader <filename>");
            return -1;
        }

        //EnumerateMasterKeys(masterKeySearchPath);

        Console.WriteLine("[*] Done.");
        return 0;
    }

    public static void EnumerateMasterKeys(string masterKeyPath)
    {
        //  Get the current account token
#pragma warning disable CA1416 // Validate platform compatibility
        IntPtr accountToken = System.Security.Principal.WindowsIdentity.GetCurrent().Token;
#pragma warning restore CA1416 // Validate platform compatibility
        if (debugMode)
        {
            Console.WriteLine("[>] Token number is: " + accountToken.ToString());
        }

        // Construct a WindowsIdentity object using the input account token.
#pragma warning disable CA1416 // Validate platform compatibility
        System.Security.Principal.WindowsIdentity windowsIdentity = new System.Security.Principal.WindowsIdentity(accountToken);
#pragma warning restore CA1416 // Validate platform compatibility
        if (debugMode)
        {
#pragma warning disable CA1416 // Validate platform compatibility
            Console.WriteLine("[>] Created a Windows identity object named " + windowsIdentity.Name + ".");
#pragma warning restore CA1416 // Validate platform compatibility
        }

        //  Obtain the SID from the Principal
#pragma warning disable CA1416 // Validate platform compatibility
        System.Security.Principal.SecurityIdentifier? si = windowsIdentity.Owner;
#pragma warning restore CA1416 // Validate platform compatibility
        if (debugMode)
        {
            Console.WriteLine("[>] Obtained Security Identifier from identity object: " + si + ".");
        }

        //  master key file search without any byte analysis
        Console.WriteLine("[>] Running master key file enumeration...");
        EnumerationOptions enumOptions = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, ReturnSpecialDirectories = true, AttributesToSkip = FileAttributes.None };
        IEnumerable<string> fileList = Directory.EnumerateFiles(masterKeyPath, "*", enumOptions);

        Console.WriteLine("[>] Listing master key files:");
        foreach (string currentFile in fileList)
        {
            bool isPreferredFile = false;
            if (currentFile.Contains("Preferred"))
            {
                isPreferredFile = true;
            }

            Console.WriteLine("[>] Processing {0}", currentFile);

#pragma warning disable CA1416 // Validate platform compatibility
            if(si != null) {
                if (currentFile.Contains(si.ToString()))
                {
                    Console.WriteLine("[!] Found the SID for the current user");
                }
            }
#pragma warning restore CA1416 // Validate platform compatibility
            if (isPreferredFile)
            {
                Console.WriteLine("[>] Found 'Preferred' file: {0}", currentFile);
            }
            else
            {
                Console.WriteLine("[>] Found master key file: {0}", currentFile);
            }
            int directoryIndex = currentFile.LastIndexOf('\\');
            if(directoryIndex > 0) {
                string keyGuid = currentFile.Substring(directoryIndex + 1);     //  chop off the beginning and the slash
                Console.WriteLine("[>] GUID: {0}", keyGuid);
                // TODO: inventory GUIDs in a hashlist
            }
        }
    }

    public static void ParseMasterKey(string currentFile)
    {
        Console.WriteLine($"[>] Parsing master key file: {currentFile}");
        // FileStream byte processing based on the FileStream.Read Method reference
        try
        {
            using (FileStream fs = File.OpenRead(currentFile))
            {
                bool isPreferredFile = false;
                if (currentFile.Contains("Preferred"))
                {
                    Console.WriteLine($"[>] Found preferred file: {currentFile}");
                    isPreferredFile = true;
                }

                if (debugMode)
                {
                    Console.WriteLine("[>] Processing filename: {0} with filesize: {1}", currentFile, fs.Length);
                }

                //  check file length before attempting byte array processing
                if (fs.Length > Int32.MaxValue)
                {
                    Console.WriteLine("[!] File too large, skipping: {0}", currentFile);
                }
                else
                {
                    if (debugMode)
                    {
                        Console.WriteLine("[>] Reading input bytes");
                    }

                    byte[] inputBytes = new byte[fs.Length];
                    int numBytesToRead = (int)fs.Length;

                    int numBytesRead = 0;
                    while (numBytesToRead > 0)
                    {
                        // read bytes
                        int n = fs.Read(inputBytes, numBytesRead, numBytesToRead);

                        // Break if the end of the file is reached first
                        if (n == 0)
                            break;

                        numBytesRead += n;
                        numBytesToRead -= n;
                    }

                    if (debugMode)
                    {
                        Console.WriteLine("[>] Done reading file bytes.");
                    }

                    if (isPreferredFile)
                    {
                        // extract preferred key guid value
                        byte[] masterKeyGuid = new byte[16];
                        Array.Copy(inputBytes, 0, masterKeyGuid, 0, masterKeyGuid.Length);
                        Guid mkGuid = new Guid(masterKeyGuid);
                        //  output preferred key guid value
                        Console.Write("Preferred Master Key GUID:\t\t\t");
                        PrintValues(masterKeyGuid, false);
                        Console.WriteLine($":({mkGuid})");
                    }
                    else
                    {
                        if (verboseMode)
                        {
                            PrintValues(inputBytes, true);
                        }

                        //  Generate hashes of input bytes
                        byte[] md5FileHash = System.Security.Cryptography.MD5.HashData(inputBytes);
                        byte[] sha1FileHash = System.Security.Cryptography.SHA1.HashData(inputBytes);
                        byte[] sha256FileHash = System.Security.Cryptography.SHA256.HashData(inputBytes);

                        Console.Write("[>] md5 Input Hash:\t\t");
                        PrintValues(md5FileHash, true);
                        Console.Write("[>] SHA-1 Input Hash:\t\t");
                        PrintValues(sha1FileHash, true);
                        Console.Write("[>] SHA-256 Input Hash:\t\t");
                        PrintValues(sha256FileHash, true);

                        //  file structure https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_dpapi.h#L80 (_KULL_M_DPAPI_MASTERKEYS)
                        byte[] dwVersion = new byte[4];
                        byte[] dwField1 = new byte[4];
                        byte[] dwField2 = new byte[4];

                        byte[] masterKeyGuid = new byte[72];

                        byte[] dwField3 = new byte[4];
                        byte[] dwField4 = new byte[4];

                        byte[] policy = new byte[4];

                        byte[] masterKeyLen = new byte[8];
                        byte[] backupKeyLen = new byte[8];
                        byte[] credHistLen = new byte[8];
                        byte[] domainKeyLen = new byte[8];

                        uint masterKeyLength;       //  dwField
                        int masterKeyDataLength;    //  int cast, probably not necessary

                        uint backupKeyLength;       //  dwField
                        int backupKeyDataLength;    //  int cast, probably not necessary

                        uint credHistLength;        //  dwField, no int cast needed

                        uint domainKeyLength;       //  dwField
                        int domainKeyDataLength;    //  int cast, probably not necessary

                        //  masterKey structure, with pKey bytes unallocated, https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_dpapi.h#L56 (_KULL_M_DPAPI_MASTERKEY)
                        byte[] mkVersion = new byte[4];                  //  version
                        byte[] mkSalt = new byte[16];                 //  salt
                        byte[] mkPBKDF2IterationCount = new byte[4];    //  rounds
                        byte[] mkHMACAlgId = new byte[4];                 //  hmac
                        byte[] mkCryptAlgId = new byte[4];                //  alg_id

                        //  backupKey structure, with pKey bytes unallocated, https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_dpapi.h#L56 (_KULL_M_DPAPI_MASTERKEY)
                        byte[] bkVersion = new byte[4];                  //  version
                        byte[] bkSalt = new byte[16];                 //  salt
                        byte[] bkPBKDF2IterationCount2 = new byte[4];   //  rounds
                        byte[] bkHMACAlgId = new byte[4];                //  hmac
                        byte[] bkCryptAlgId = new byte[4];               //  alg_id

                        // process blob
                        int ptrFile = 0;

                        Console.WriteLine("[ MasterKey Binary Structure ]");

                        Array.Copy(inputBytes, ptrFile, dwVersion, 0, dwVersion.Length);
                        ptrFile += dwVersion.Length;
                        Console.Write("dwVersion:\t\t\t");
                        PrintValues(dwVersion, true);

                        Array.Copy(inputBytes, ptrFile, dwField1, 0, dwField1.Length);
                        ptrFile += dwField1.Length;
                        Console.Write("dwField1:\t\t\t");
                        PrintValues(dwField1, true);

                        Array.Copy(inputBytes, ptrFile, dwField2, 0, dwField2.Length);
                        ptrFile += dwField2.Length;
                        Console.Write("dwField2:\t\t\t");
                        PrintValues(dwField2, true);

                        Array.Copy(inputBytes, ptrFile, masterKeyGuid, 0, masterKeyGuid.Length);
                        Console.Write("masterKeyGuid:\t\t\t");
                        PrintValues(masterKeyGuid, true);
                        ptrFile += masterKeyGuid.Length;

                        Array.Copy(inputBytes, ptrFile, dwField3, 0, dwField3.Length);
                        Console.Write("dwField3:\t\t\t");
                        PrintValues(dwField3, true);
                        ptrFile += dwField3.Length;

                        Array.Copy(inputBytes, ptrFile, dwField4, 0, dwField4.Length);
                        Console.Write("dwField4\t\t\t");
                        PrintValues(dwField4, true);
                        ptrFile += dwField4.Length;

                        Array.Copy(inputBytes, ptrFile, policy, 0, policy.Length);
                        Console.Write("policy:\t\t\t\t");
                        PrintValues(policy, true);
                        ptrFile += policy.Length;

                        Console.WriteLine("[ Length Fields ]");

                        Array.Copy(inputBytes, ptrFile, masterKeyLen, 0, masterKeyLen.Length);
                        masterKeyLength = ByteArrayToUint(masterKeyLen);
                        ptrFile += masterKeyLen.Length;
                        Console.Write("masterKeyLen:\t\t\t");
                        PrintValues(masterKeyLen, false);
                        Console.WriteLine($":({masterKeyLength})");

                        Array.Copy(inputBytes, ptrFile, backupKeyLen, 0, backupKeyLen.Length);
                        backupKeyLength = ByteArrayToUint(backupKeyLen);
                        ptrFile += backupKeyLen.Length;
                        Console.Write("backupKeyLen:\t\t\t");
                        PrintValues(backupKeyLen, false);
                        Console.WriteLine($":({backupKeyLength})");

                        Array.Copy(inputBytes, ptrFile, credHistLen, 0, credHistLen.Length);
                        credHistLength = ByteArrayToUint(credHistLen);
                        ptrFile += credHistLen.Length;
                        Console.Write("credHistLen:\t\t\t");
                        PrintValues(credHistLen, false);
                        Console.WriteLine($":({credHistLength})");

                        Array.Copy(inputBytes, ptrFile, domainKeyLen, 0, domainKeyLen.Length);
                        domainKeyLength = ByteArrayToUint(domainKeyLen);
                        ptrFile += domainKeyLen.Length;
                        Console.Write("domainKeyLen:\t\t\t");
                        PrintValues(domainKeyLen, false);
                        Console.WriteLine($":({domainKeyLength})");

                        //  master key parsing
                        Console.WriteLine("[ MasterKey Structure ]");

                        Array.Copy(inputBytes, ptrFile, mkVersion, 0, mkVersion.Length);
                        Console.Write("mkVersion:\t\t\t");
                        PrintValues(mkVersion, true);
                        ptrFile += mkVersion.Length;

                        Array.Copy(inputBytes, ptrFile, mkSalt, 0, mkSalt.Length);
                        Console.Write("mkSalt:\t\t\t\t");
                        PrintValues(mkSalt, true);
                        ptrFile += mkSalt.Length;

                        Array.Copy(inputBytes, ptrFile, mkPBKDF2IterationCount, 0, mkPBKDF2IterationCount.Length);
                        Console.Write("mkPBKDF2IterationCount:\t\t");
                        PrintValues(mkPBKDF2IterationCount, true);
                        ptrFile += mkPBKDF2IterationCount.Length;

                        Array.Copy(inputBytes, ptrFile, mkHMACAlgId, 0, mkHMACAlgId.Length);
                        Console.Write("mkHMACAlgId:\t\t\t");
                        PrintValues(mkHMACAlgId, true);
                        ptrFile += mkHMACAlgId.Length;

                        Array.Copy(inputBytes, ptrFile, mkCryptAlgId, 0, mkCryptAlgId.Length);
                        Console.Write("mkCryptAlgId:\t\t\t");
                        PrintValues(mkCryptAlgId, true);
                        ptrFile += mkCryptAlgId.Length;

                        //  master key data length calculation
                        masterKeyDataLength = (int)masterKeyLength - mkPBKDF2IterationCount.Length - mkHMACAlgId.Length - mkCryptAlgId.Length - mkSalt.Length - mkVersion.Length;
                        Console.WriteLine($"masterKeyDataLength:\t\t{masterKeyDataLength}");

                        byte[] masterKeyData = new byte[masterKeyDataLength];
                        Array.Copy(inputBytes, ptrFile, masterKeyData, 0, masterKeyData.Length);
                        Console.Write("masterKeyData:\t\t\t");
                        PrintValues(masterKeyData, true);
                        ptrFile += (int)masterKeyDataLength;

                        //  backup key processing
                        Console.WriteLine("[ BackupKey Structure ]");

                        Array.Copy(inputBytes, ptrFile, bkVersion, 0, bkVersion.Length);
                        Console.Write("bkVersion:\t\t\t");
                        PrintValues(bkVersion, true);
                        ptrFile += bkVersion.Length;

                        Array.Copy(inputBytes, ptrFile, bkSalt, 0, bkSalt.Length);
                        Console.Write("bkSalt:\t\t\t\t");
                        PrintValues(bkSalt, true);
                        ptrFile += bkSalt.Length;

                        Array.Copy(inputBytes, ptrFile, bkPBKDF2IterationCount2, 0, bkPBKDF2IterationCount2.Length);
                        Console.Write("bkPBKDF2IterationCount2:\t");
                        PrintValues(bkPBKDF2IterationCount2, true);
                        ptrFile += bkPBKDF2IterationCount2.Length;

                        Array.Copy(inputBytes, ptrFile, bkHMACAlgId, 0, bkHMACAlgId.Length);
                        Console.Write("bkHMACAlgId2:\t\t\t");
                        PrintValues(bkHMACAlgId, true);
                        ptrFile += bkHMACAlgId.Length;

                        Array.Copy(inputBytes, ptrFile, bkCryptAlgId, 0, bkCryptAlgId.Length);
                        Console.Write("bkCryptAlgId2:\t\t\t");
                        PrintValues(bkCryptAlgId, true);
                        ptrFile += bkCryptAlgId.Length;

                        //  backup key data length calculation
                        backupKeyDataLength = (int)backupKeyLength - bkPBKDF2IterationCount2.Length - bkHMACAlgId.Length - bkCryptAlgId.Length - bkSalt.Length - bkVersion.Length;
                        Console.WriteLine($"backupKeyDataLength:\t\t{backupKeyDataLength}");

                        byte[] backupKeyData = new byte[backupKeyDataLength];
                        Array.Copy(inputBytes, ptrFile, backupKeyData, 0, backupKeyDataLength);
                        Console.Write("backupKeyData:\t\t\t");
                        PrintValues(backupKeyData, true);
                        ptrFile += (int)backupKeyDataLength;

                        //  credential history parsing
                        if (credHistLength > 0)
                        {
                            Console.WriteLine("[ CredHist Structure ]");

                            //  process credHist   
                            byte[] credHistVerion = new byte[4];
                            byte[] credHistGuid = new byte[16];
                            Array.Copy(inputBytes, ptrFile, credHistVerion, 0, credHistVerion.Length);
                            Console.Write("credHistVerion:\t\t\t");
                            PrintValues(credHistVerion, true);
                            ptrFile += credHistVerion.Length;

                            Array.Copy(inputBytes, ptrFile, credHistGuid, 0, credHistGuid.Length);
                            Console.Write("credHistGuid:\t\t\t");
                            PrintValues(credHistGuid, true);
                            ptrFile += credHistGuid.Length;
                        }

                        //  domain key parsing
                        if (domainKeyLength > 0)
                        {
                            byte[] dkVersion = new byte[4];
                            byte[] dkSecretLen = new byte[4];
                            byte[] dkAccesCheckLen = new byte[4];

                            Console.WriteLine("[ DomainKey Structure ]");

                            Array.Copy(inputBytes, ptrFile, dkVersion, 0, dkVersion.Length);
                            Console.Write("dkVersion:\t\t\t");
                            PrintValues(dkVersion, true);
                            ptrFile += dkVersion.Length;

                            Array.Copy(inputBytes, ptrFile, dkSecretLen, 0, dkSecretLen.Length);
                            ptrFile += dkSecretLen.Length;
                            uint dkSecretLength = ByteArrayToUint(dkSecretLen);
                            Console.Write("dkSecretLen:\t\t\t");
                            PrintValues(dkSecretLen, false);
                            Console.WriteLine($":({dkSecretLength})");

                            Array.Copy(inputBytes, ptrFile, dkAccesCheckLen, 0, dkAccesCheckLen.Length);
                            ptrFile += dkAccesCheckLen.Length;
                            uint dkAccessCheckLength = ByteArrayToUint(dkAccesCheckLen);
                            Console.Write("dkAccesCheckLen:\t\t");
                            PrintValues(dkAccesCheckLen, false);
                            Console.WriteLine($":({dkAccessCheckLength})");

                            //  wait, is there a guid in here? how would the bytes still line up?
                            byte[] dkMasterKeyGuid = new byte[16];
                            Array.Copy(inputBytes, ptrFile, dkMasterKeyGuid, 0, dkMasterKeyGuid.Length);
                            Console.Write("dkMasterKeyGuid:\t\t");
                            PrintValues(dkMasterKeyGuid, true);
                            ptrFile += dkMasterKeyGuid.Length;

                            // domain key data length calculation
                            domainKeyDataLength = (int)domainKeyLength - (int)dkAccessCheckLength - dkMasterKeyGuid.Length - dkAccesCheckLen.Length - dkSecretLen.Length - dkVersion.Length;
                            Console.WriteLine($"domainKeyDataLength:\t\t{domainKeyDataLength}");

                            byte[] domainBackupKeyData = new byte[domainKeyDataLength];
                            Array.Copy(inputBytes, ptrFile, domainBackupKeyData, 0, domainKeyDataLength);
                            Console.Write("domainBackupKeyData:\t\t");
                            PrintValues(domainBackupKeyData, true);
                            ptrFile += (int)domainKeyDataLength;

                            byte[] accessCheckData = new byte[dkAccessCheckLength];
                            Array.Copy(inputBytes, ptrFile, accessCheckData, 0, dkAccessCheckLength);
                            Console.Write("accessCheckData:\t\t");
                            PrintValues(accessCheckData, true);
                            ptrFile += (int)dkAccessCheckLength;
                        }
                        if (debugMode)
                        {
                            int remainingBytes = numBytesRead - ptrFile;    //  anything left in the file?
                            Console.WriteLine("[*] DEBUG File Processing Data");
                            Console.WriteLine("[>] File pointer ending value:{0}", ptrFile);
                            Console.WriteLine("[>] Remaining bytes:{0}", remainingBytes);
                        }
                    }
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("ERROR: Exception {0}", e.Message);
        }
        Console.WriteLine("[>] MasterKey parsing complete.");
    }

    public static uint ByteArrayToUint(byte[] inputArray)
    {
        /*if (inputArray == null || inputArray.Length != 4)
        {
            throw new ArgumentException("[ERROR] Byte array must be 4 bytes.");
        }*/

        //  maybe for readability?
        /*if (BitConverter.IsLittleEndian)
            Array.Reverse(inputArray);*/

        uint i = BitConverter.ToUInt32(inputArray, 0);
        return i;
    }

    // Adapted from Microsoft's DPAPI examples
    public static void PrintValues(Byte[] myArr, bool addNewline = false)
    {
        Console.Write("0x");
        foreach (Byte i in myArr)
        {
            //  added .ToString("X2") to format the byte values in hex
            //Console.Write( "\t{0}", i );
            //Console.Write("0x{0}", i.ToString("X2"));
            Console.Write("{0}", i.ToString("x2"));     //  lowercase seems better for readability
        }
        if (addNewline)
            Console.WriteLine();
    }

    public static int ByteArrayToInt(byte[] bytes, bool isLittleEndian = true)
    {
        if (bytes == null || bytes.Length != 4)
        {
            throw new ArgumentException("Byte array must have exactly 4 bytes.");
        }

        byte[] buffer = new byte[4];
        Buffer.BlockCopy(bytes, 0, buffer, 0, 4);

        if ((BitConverter.IsLittleEndian && !isLittleEndian) || (!BitConverter.IsLittleEndian && isLittleEndian))
        {
            //Array.Reverse(buffer);
        }

        return BitConverter.ToInt32(buffer, 0);
    }

    public static int IndexOfBytes(this byte[] source, byte[] pattern)
    {
        // handle nulls, empty pattern, or pattern longer than source
        if (source == null || pattern == null || pattern.Length == 0 || source.Length < pattern.Length)
        {
            return -1;
        }

        for (int i = 0; i <= source.Length - pattern.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
            {
                return i; // Return the starting index of the found pattern
            }
        }
        return -1; // Pattern not found
    }

}