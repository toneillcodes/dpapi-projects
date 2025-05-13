using System;
using System.Security.Cryptography;
using System.Security.Permissions;
using Microsoft.Win32;

public class DPAPIDataExample {
    static byte[] entropyBits = {1,2,3,4,5};      //  "That's the kind of thing an idiot would have on his luggage"
    static string plaintextFilePath = @"C:\dev\training\dpapi\tmp\plaintext.txt";
    static string encryptedFilePath = @"C:\dev\training\dpapi\tmp\encrypted.txt";
    static string encryptedOutputFilePath = @"C:\dev\training\dpapi\tmp\encrypted.out";
    static string unprotectedOutputFilePath = @"C:\dev\training\dpapi\tmp\decrypted.out";
    static string registryKeyPath ="Software\\Sysinternals\\DPAPIPoC";
    static string registryValueName = "TopSecretBlob";

    public static void Main(string[] args){
        byte[] mySecretBytes;
        Console.WriteLine("[*] Starting ProtectedData example...");
        
        //  Remove encrypted output file
        if (File.Exists(encryptedOutputFilePath))
        {
            File.Delete(encryptedOutputFilePath);
        }        

        //  Remove decrypted output file
        if (File.Exists(unprotectedOutputFilePath))
        {
            File.Delete(unprotectedOutputFilePath);
        }        

        Console.WriteLine("[*] Starting protection routine");

        //	Check for plaintext input file, read contents, protect contents and write bytes to protected output file
        if (File.Exists(plaintextFilePath))
        {
            Console.WriteLine("[*] Reading secret value from path: {0}", plaintextFilePath);
            // FileStream byte processing based on the FileStream.Read Method reference
            using (FileStream plaintextFs = File.OpenRead(plaintextFilePath)) {
                // Read the source file into a byte array.
                byte[] plaintextBytes = new byte[plaintextFs.Length];
                int numBytesToRead = (int)plaintextFs.Length;
                int numBytesRead = 0;
                while (numBytesToRead > 0)
                {
                    // Read may return anything from 0 to numBytesToRead.
                    int n = plaintextFs.Read(plaintextBytes, numBytesRead, numBytesToRead);

                    // Break when the end of the file is reached.
                    if (n == 0)
                        break;

                    numBytesRead += n;
                    numBytesToRead -= n;
                }

                //	Secret data
                mySecretBytes = plaintextBytes;
            }
        } else {
            //	Secret data
            string mySecretValue = "maytheschwartzbewithyou";
            mySecretBytes = System.Text.Encoding.UTF8.GetBytes(mySecretValue);
            Console.WriteLine("[*] Using static secret value: {0}", mySecretValue);
        }

        /************************************************/
        /* Valid DataProtectionScope values:            */
        /*  DataProtectionScope.CurrentUser (0)         */
        /*  DataProtectionScope.LocalMachine (1)        */
        /************************************************/
        // byte[] encryptedSecret = ProtectedData.Protect(mySecretBytes, entropyBits, DataProtectionScope.CurrentUser);
        byte[] protectedSecret = ProtectedData.Protect(mySecretBytes, entropyBits, DataProtectionScope.LocalMachine);

        Console.WriteLine("The protected byte array:");
		PrintValues(protectedSecret);

        // Write the encrypted bytes to the encrypted output file
        using (FileStream encryptedOutputFs = File.Create(encryptedOutputFilePath))
        {
            encryptedOutputFs.Write(protectedSecret, 0, protectedSecret.Length);
            Console.WriteLine("[*] Encrypted output file written.");
        }

        Console.WriteLine("[*] Starting unprotection routine");

        //	Check for encrypted input file, read contents, unprotect contents and write bytes to unprotected output file
        if (File.Exists(encryptedFilePath))
        {
            Console.WriteLine("[*] Reading encrypted bytes from path: {0}", encryptedFilePath);
            // FileStream byte processing based on the FileStream.Read Method reference
            using (FileStream encryptedInputFs = File.OpenRead(encryptedFilePath)) {
                // Read the source file into a byte array.
                byte[] encryptedBytes = new byte[encryptedInputFs.Length];
                int numBytesToRead = (int)encryptedInputFs.Length;
                int numBytesRead = 0;
                while (numBytesToRead > 0)
                {
                    // Read may return anything from 0 to numBytesToRead.
                    int n = encryptedInputFs.Read(encryptedBytes, numBytesRead, numBytesToRead);

                    // Break when the end of the file is reached.
                    if (n == 0)
                        break;

                    numBytesRead += n;
                    numBytesToRead -= n;
                }
                
                /************************************************/
                /* Valid DataProtectionScope values:            */
                /*  DataProtectionScope.CurrentUser (0)         */
                /*  DataProtectionScope.LocalMachine (1)        */
                /************************************************/
                // byte[] unprotectedBytes = ProtectedData.Unprotect(encryptedSecret, entropyBits, DataProtectionScope.CurrentUser);
                byte[] unprotectedBytes = ProtectedData.Unprotect(encryptedBytes, entropyBits, DataProtectionScope.LocalMachine);
                
                Console.WriteLine("The unprotected byte array:");
		        PrintValues(unprotectedBytes);

                string unprotectedValue = System.Text.Encoding.UTF8.GetString(unprotectedBytes);
                Console.WriteLine("The unprotected string value: {0}", unprotectedValue);

                // Write the encrypted bytes to the encrypted output file
                using (FileStream decryptedOutputFs = File.Create(unprotectedOutputFilePath))
                {
                    decryptedOutputFs.Write(unprotectedBytes, 0, unprotectedBytes.Length);
                    Console.WriteLine("[*] Unprotected output file written.");
                }
            }
        } else {
            Console.WriteLine("[*] No encrypted input found, skipping decryption");
        }

        Console.WriteLine("[*] Starting registry storage routine");

        string encodedSecret = Convert.ToBase64String(protectedSecret);
        //Console.WriteLine("Base64 encoded secret bytes: {0}", encodedSecret);

        //RegistryKey rk = Registry.LocalMachine;
        RegistryKey rk = Registry.CurrentUser;

        // create a subkey named DPAPIPoC under HKEY_CURRENT_USER\Software\Sysinternals\DPAPIPoC.
        RegistryKey rkDPAPIPoC = rk.CreateSubKey(registryKeyPath);
        
        // create data for the TopSecretBlob subkey.
        rkDPAPIPoC.SetValue(registryValueName, encodedSecret);

        Console.WriteLine("[*] Secret stored under registry key (HKEY_CURRENT_USER): {0}", registryKeyPath);

        Console.WriteLine("[*] Done.");
    }
	
    // Copied from Microsoft's DPAPI examples
    public static void PrintValues(Byte[] myArr)
    {
        foreach(Byte i in myArr)
        {
            //Console.Write( "\t{0}", i );
            Console.Write("0x{0} ",i.ToString("X2"));
        }
        Console.WriteLine();
    }
}
