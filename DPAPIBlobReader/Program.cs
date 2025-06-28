using System.Security.AccessControl;

public static class DPAPIBlobReader
{
    static byte[] magicBytes = { 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB };
    //static string filename = @"C:\dev\training\dpapi\tmp\encrypted.out";

    static bool debug = false;
    static bool logging = false;
    static bool findMasterKey = false;
    static string masterKeyPath = @"C:\Users\$USER\AppData\Roaming\Microsoft\Protect";
    public static int Main(string[] args)
    {
        bool fileProvided = false;
        string outputOption = "";
        bool outputBytes = false;
        bool outputStdout = false;
        bool outputFile = false;
        string fileParam = "";
        string outputFilename = "";

        string filename = "";
        if (args.Length >= 1)
        {
            foreach (var arg in args)
            {
                if (arg.StartsWith("/file:"))
                {
                    //  parse the option value
                    int separatorIndex = arg.IndexOf(':');
                    if (separatorIndex > -1)
                    {
                        string fileCmd = arg.Substring(0, separatorIndex).Trim();
                        filename = arg.Substring(separatorIndex + 1).Trim();
                        if (filename.Length <= 0)
                        {
                            Console.WriteLine("[ERROR] Filename required!");
                            Console.WriteLine("Usage: DPAPIBlobReader /file:<filename> /stdout /outfile:<filename>");
                            return -1;                             
                        }
                        Console.WriteLine($"Processing filename: {filename}");
                        fileProvided = true;
                    }
                }
                else if (arg.StartsWith("/outfile:"))
                {
                    outputFile = true;
                    //  parse the option value
                    int separatorIndex = arg.IndexOf(':');
                    if (separatorIndex > -1)
                    {
                        string fileCmd = arg.Substring(0, separatorIndex).Trim();
                        outputFilename = arg.Substring(separatorIndex + 1).Trim();
                        if (outputFilename.Length <= 0)
                        {
                            Console.WriteLine("[ERROR] Output parameter provided but filename is missing, skipping file ouput.");
                            outputFile = false;
                        }
                    }
                }
                else if (arg.Equals("/stdout"))
                {
                    outputStdout = true;
                }
            }
            if (!fileProvided)
            {
                Console.WriteLine("[ERROR] Filename required!");
                Console.WriteLine("Usage: DPAPIBlobReader /file:<filename> /stdout /outfile:<filename>");
                return -1;                
            }
        }
        else
        {
            Console.WriteLine("[ERROR] Filename required!");
            Console.WriteLine("Usage: DPAPIBlobReader /file:<filename> /stdout /outfile:<filename>");
            return -1;
        }

        // FileStream byte processing based on the FileStream.Read Method reference
        try
        {
            using (FileStream fs = File.OpenRead(filename))
            {
                if (debug)
                {
                    Console.WriteLine("[*] Processing filename: {0}", filename);
                }
                if (fs.Length > Int32.MaxValue)
                {
                    Console.WriteLine("[!] File too large, skipping: {0}", filename);
                }
                else
                {
                    byte[] inputBytes = new byte[fs.Length];
                    int numBytesToRead = (int)fs.Length;

                    int numBytesRead = 0;
                    while (numBytesToRead > 0)
                    {
                        // read bytes
                        int n = fs.Read(inputBytes, numBytesRead, numBytesToRead);

                        // break if the end of the file is reached first
                        if (n == 0)
                            break;

                        numBytesRead += n;
                        numBytesToRead -= n;
                    }
                    byte[] fileHash = System.Security.Cryptography.SHA256.HashData(inputBytes);

                    //  we want to start processing from the beginning of our blog magic bytes, which may not be the beginning of the file
                    int blobStart = IndexOfBytes(inputBytes, magicBytes);
                    if (blobStart < 0)
                    {
                        Console.WriteLine("[!] ERROR: Unable to locate the blob start using magic bytes, exiting.");
                        return -1;
                    }

                    //  DPAPI blob structure, based on mimikatz DPAPI structure (https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_dpapi.h#L24)
                    byte[] dwVersion = new byte[4];
                    byte[] guidProvider = new byte[16];
                    byte[] dwMasterKeyVersion = new byte[4];
                    byte[] guidMasterKey = new byte[16];
                    byte[] dwFlags = new byte[4];
                    byte[] dwDescriptionLen = new byte[4];
                    // byte[] szDescription = new byte[8];       //  4/32, 8/64: dynamic length
                    byte[] algCrypt = new byte[4];
                    byte[] dwAlgCryptLen = new byte[4];
                    byte[] dwSaltLen = new byte[4];
                    // byte[] pbSalt = new byte[4];             //  4/32, 8/64: dynamic length
                    byte[] dwHmacKeyLen = new byte[4];
                    byte[] pbHmackKey = new byte[8];
                    byte[] algHash = new byte[4];
                    byte[] dwAlgHashLen = new byte[4];
                    byte[] dwHmac2KeyLen = new byte[4];
                    // byte[] pbHmack2Key = new byte[4];        //  4/32, 8/64: dynamic length
                    byte[] dwDataLen = new byte[4];
                    byte[] dwSignLen = new byte[4];
                    // byte[] pbSign = new byte[4];             //  4/32, 8/64: dynamic length

                    // process blob
                    int ptrBlob = blobStart;
                    //  dwVersion
                    Array.Copy(inputBytes, ptrBlob, dwVersion, 0, dwVersion.Length);
                    ptrBlob += dwVersion.Length;
                    //  guidProvider
                    Array.Copy(inputBytes, ptrBlob, guidProvider, 0, guidProvider.Length);
                    Guid dpapiGuid = new Guid(guidProvider);
                    ptrBlob += guidProvider.Length;
                    //  dwMasterKeyVersion
                    Array.Copy(inputBytes, ptrBlob, dwMasterKeyVersion, 0, dwMasterKeyVersion.Length);
                    ptrBlob += dwMasterKeyVersion.Length;
                    //  masterKeyGuid
                    Array.Copy(inputBytes, ptrBlob, guidMasterKey, 0, guidMasterKey.Length);
                    Guid masterKeyGuid = new Guid(guidMasterKey);
                    ptrBlob += guidMasterKey.Length;
                    //  dwFlags
                    Array.Copy(inputBytes, ptrBlob, dwFlags, 0, dwFlags.Length);
                    ptrBlob += dwFlags.Length;
                    //  dwDescriptionLen
                    Array.Copy(inputBytes, ptrBlob, dwDescriptionLen, 0, dwDescriptionLen.Length);
                    ptrBlob += dwDescriptionLen.Length;
                    //  convert byte array to uint
                    uint descriptionLength = ByteArrayToUint(dwDescriptionLen);
                    //  allocate byte array for szDescription
                    byte[] szDescription = new byte[descriptionLength];
                    //  szDescription
                    Array.Copy(inputBytes, ptrBlob, szDescription, 0, descriptionLength);
                    ptrBlob += (int)descriptionLength;
                    //  algCrypt, decode values based on: https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
                    Array.Copy(inputBytes, ptrBlob, algCrypt, 0, algCrypt.Length);
                    ptrBlob += algCrypt.Length;
                    //  dwAlgCryptLen
                    Array.Copy(inputBytes, ptrBlob, dwAlgCryptLen, 0, dwAlgCryptLen.Length);
                    ptrBlob += dwAlgCryptLen.Length;
                    //  convert byte array to uint
                    uint algCryptLen = ByteArrayToUint(dwAlgCryptLen);
                    //  dwSaltLen
                    Array.Copy(inputBytes, ptrBlob, dwSaltLen, 0, dwSaltLen.Length);
                    ptrBlob += dwSaltLen.Length;
                    //  convert byte array to uint
                    uint saltLen = ByteArrayToUint(dwSaltLen);
                    //  allocate byte array for pbSalt
                    byte[] pbSalt = new byte[saltLen];
                    //  pbSalt
                    Array.Copy(inputBytes, ptrBlob, pbSalt, 0, saltLen);
                    ptrBlob += (int)saltLen;
                    //  dwHmacKeyLen
                    Array.Copy(inputBytes, ptrBlob, dwHmacKeyLen, 0, dwHmacKeyLen.Length);
                    ptrBlob += dwHmacKeyLen.Length;
                    //  convert byte array to uint
                    uint hmacKeyLen = ByteArrayToUint(dwHmacKeyLen);
                    //  pbHmackKey
                    Array.Copy(inputBytes, ptrBlob, pbHmackKey, 0, hmacKeyLen);
                    ptrBlob += (int)hmacKeyLen;
                    //  algHash
                    Array.Copy(inputBytes, ptrBlob, algHash, 0, algHash.Length);
                    ptrBlob += algHash.Length;
                    //  dwAlgHashLen
                    Array.Copy(inputBytes, ptrBlob, dwAlgHashLen, 0, dwAlgHashLen.Length);
                    ptrBlob += dwAlgHashLen.Length;
                    //  convert byte array to uint
                    uint algHashLen = ByteArrayToUint(dwAlgHashLen);
                    //  dwHmac2KeyLen
                    Array.Copy(inputBytes, ptrBlob, dwHmac2KeyLen, 0, dwHmac2KeyLen.Length);
                    ptrBlob += dwHmac2KeyLen.Length;
                    //  convert byte array to uint
                    uint hmac2KeyLen = ByteArrayToUint(dwHmac2KeyLen);
                    //  allocate byte array for pbHmack2Key
                    byte[] pbHmack2Key = new byte[hmac2KeyLen];
                    //  pbHmack2Key
                    Array.Copy(inputBytes, ptrBlob, pbHmack2Key, 0, hmac2KeyLen);
                    ptrBlob += (int)hmac2KeyLen;
                    //  dwDataLen
                    Array.Copy(inputBytes, ptrBlob, dwDataLen, 0, dwDataLen.Length);
                    ptrBlob += dwDataLen.Length;
                    //  convert byte array to uint
                    uint dataLen = ByteArrayToUint(dwDataLen);
                    //  allocate byte array for pbData
                    byte[] pbData = new byte[dataLen];
                    //  pbData
                    Array.Copy(inputBytes, ptrBlob, pbData, 0, dataLen);
                    ptrBlob += (int)dataLen;
                    //  dwSignLen
                    Array.Copy(inputBytes, ptrBlob, dwSignLen, 0, dwSignLen.Length);
                    ptrBlob += dwSignLen.Length;
                    //  convert byte array to uint
                    uint signLen = ByteArrayToUint(dwSignLen);
                    //  allocate byte array for pbSign
                    byte[] pbSign = new byte[signLen];
                    //  pbSign
                    Array.Copy(inputBytes, ptrBlob, pbSign, 0, signLen);
                    ptrBlob += (int)signLen;

                    //  anything left in the file?
                    int remainingBytes = numBytesRead - ptrBlob;

                    //  output blob summary
                    Console.WriteLine("[*] Blob Summary");
                    Console.WriteLine("[>] Filename: {0}", filename);
                    Console.Write("[>] File hash (SHA-256): ");
                    PrintValues(fileHash, true, true);
                    Console.WriteLine("[>] Blob start position: {0}.", blobStart);
                    Console.WriteLine("[>] Final blob pointer position: {0}", ptrBlob);
                    Console.WriteLine("[>] Remaining bytes: {0}", remainingBytes);
                    Console.WriteLine("[>] Blob Structure:");
                    Console.Write("dwVerion:\t\t\t");
                    PrintValues(dwVersion, true, true);
                    Console.Write("guidProvider:\t\t\t");
                    PrintValues(guidProvider, false, true);
                    Console.WriteLine(":({0})", dpapiGuid.ToString());
                    Console.Write("dwMasterKeyVersion:\t\t");
                    PrintValues(dwMasterKeyVersion, true, true);
                    Console.Write("guidMasterKey:\t\t\t");
                    PrintValues(guidMasterKey, false, true);
                    Console.WriteLine(":({0})", masterKeyGuid.ToString());
                    Console.Write("dwFlags:\t\t\t");
                    PrintValues(dwFlags, true, true);
                    Console.Write("dwDescriptionLen:\t\t");
                    PrintValues(dwDescriptionLen, false, true);
                    Console.WriteLine(":({0})", descriptionLength);
                    Console.Write("szDescription:\t\t\t");
                    if (EmptyArray(szDescription)) {     //  is the description array all zeroes?
                        PrintValues(szDescription, true, true);       //  output as-is
                    }
                    else {
                        PrintValues(szDescription, false, true);
                        string reableDescription = System.Text.Encoding.UTF8.GetString(szDescription);
                        Console.WriteLine("({0})", reableDescription);
                    }
                    Console.Write("algCrypt:\t\t\t");
                    PrintValues(algCrypt, true, true);
                    Console.Write("dwAlgCryptLen:\t\t\t");
                    PrintValues(dwAlgCryptLen, false, true);
                    Console.WriteLine(":({0})", algCryptLen);
                    Console.Write("dwSaltLen:\t\t\t");
                    PrintValues(dwSaltLen, false, true);
                    Console.WriteLine(":({0})", saltLen);
                    Console.Write("pbSalt:\t\t\t\t");
                    PrintValues(pbSalt, true, true);
                    Console.Write("dwHmacKeyLen:\t\t\t");
                    PrintValues(dwHmacKeyLen, false, true);
                    Console.WriteLine(":({0})", hmacKeyLen);
                    Console.Write("pbHmackKey:\t\t\t");
                    PrintValues(pbHmackKey, true, true);
                    Console.Write("algHash:\t\t\t");
                    PrintValues(algHash, true, true);
                    Console.Write("dwAlgHashLen:\t\t\t");
                    PrintValues(dwAlgHashLen, false, true);
                    Console.WriteLine(":({0})", algHashLen);
                    Console.Write("dwHmac2KeyLen:\t\t\t");
                    PrintValues(dwHmac2KeyLen, false, true);
                    Console.WriteLine(":({0})", hmac2KeyLen);
                    Console.Write("pbHmack2Key:\t\t\t");
                    PrintValues(pbHmack2Key, true, true);
                    Console.Write("dwDataLen:\t\t\t");
                    PrintValues(dwDataLen, false, true);
                    Console.WriteLine(":({0})", dataLen);
                    Console.Write("pbData:\t\t\t\t");
                    PrintValues(pbData, true, true);
                    Console.Write("dwSignLen:\t\t\t");
                    PrintValues(dwSignLen, false, true);
                    Console.WriteLine(":({0})", signLen);
                    Console.Write("pbSign:\t\t\t\t");
                    PrintValues(pbSign, true, true);

                    if (outputStdout) {
                        Console.WriteLine("[*] Output to stdout enabled, dumping bytes:");
                        Console.WriteLine("--------START--------");
                        PrintValues(inputBytes, true, false);
                        Console.WriteLine("---------EOF---------");                        
                    }

                    if (outputFile)
                    {
                        Console.WriteLine($"[*] Output to file enabled, dumping bytes to file: {outputFilename}");
                        
                        //  Remove decrypted output file
                        if (File.Exists(outputFilename))
                        {
                            File.Delete(outputFilename);
                        }     

                        // Write the encrypted bytes to the encrypted output file
                        using (FileStream outputFs = File.Create(outputFilename))
                        {
                            outputFs.Write(inputBytes, 0, inputBytes.Length);
                            Console.WriteLine("[*] Output file written.");
                        }
                    }

                    Console.WriteLine("[*] Done.");
                }
            }
        }
        catch (Exception e)
        {
            if (debug)
            {
                Console.WriteLine("ERROR: Exception: {0}", e.Message);
                return -1;
            }
        }
        return 0;
    }

    // Adapted from Microsoft's DPAPI examples
    public static void PrintValues(Byte[] myArr, bool addNewline = false, bool hexOutput = false)
    {
        if(hexOutput) {
            Console.Write("0x");
        }
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

    public static uint ByteArrayToUint(byte[] inputArray)
    {
        if (inputArray == null || inputArray.Length != 4)
        {
            throw new ArgumentException("[ERROR] Byte array must be 4 bytes.");
        }

        //  maybe for readability?
        /*if (BitConverter.IsLittleEndian)
            Array.Reverse(inputArray);*/

        uint i = BitConverter.ToUInt32(inputArray, 0);
        return i;
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
                return i; // return the starting index of the found pattern
            }
        }
        return -1; // pattern not found
    }
    public static bool EmptyArray(byte[] source)
    {
        foreach (byte i in source)
        {
            if (i != 0)
            {
                return false;
            }
        }
        return true;
    }
}
