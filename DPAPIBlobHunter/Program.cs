using Microsoft.Win32;

public class DPAPIBlobHunter {
    //static byte[] magicBytes = { 1, 0, 0, 0, 208, 140, 157, 223, 1, 21, 209, 17, 140, 122, 0, 192, 79, 194, 151, 235 };  
    static byte[] magicBytes = { 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB };
    static string magicBytesEncoded = "AQAAANCMnd8BFdERjHoAwE/Cl+s";
    static string registrySearchPath = "Software";

    //static string searchPath = @"C:\dev\training\";
    //static string searchPath = @"C:\dev\training\dpapi\tmp";
    //static string searchPath = @"C:\Users\<user>\AppData\Roaming";
    //static string searchPath = @"C:\Users\<user>\AppData\Local";
    //static string searchPath = @"C:\Users\<user>\AppData\Local\Microsoft";
    static string searchPath = @"C:\Users\<user>\AppData\Local\Microsoft\Credentials";

    static bool debugMode = false;

    public static void Main(string[] args) {
        
        Console.WriteLine("[*] Starting filesystem check routine");
        try
        {
            // https://learn.microsoft.com/en-us/dotnet/api/system.io.directory?view=net-9.0
            var enumOptions = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, ReturnSpecialDirectories = true, AttributesToSkip = FileAttributes.None };
            var fileList = Directory.EnumerateFiles(searchPath, "*", enumOptions);
            foreach (string currentFile in fileList)
            {
                string fileName = currentFile.Substring(searchPath.Length + 1);
                if(debugMode) {
                    Console.WriteLine("DEBUG Processing: {0}", fileName);
                }
                // FileStream byte processing based on the FileStream.Read Method reference
                try {
                    using (FileStream fs = File.OpenRead(currentFile)) {
                        if(fs.Length > Int32.MaxValue) {
                            Console.WriteLine("File too large, skipping {0}",currentFile);
                        } else {
                            if(debugMode) {
                                Console.WriteLine("DEBUG fs.length: {0}",fs.Length);
                            }
                            //byte[] inputBytes = new byte[20];
                            byte[] inputBytes = new byte[fs.Length];
                            
                            //int numBytesToRead = 20;
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

                            // verbose debug output
                            if(debugMode) {
                                //PrintValues(inputBytes);
                            }

                            // now we need to compare the bytes in inputBytes to magicBytes
                            bool comparisonResult = ContainsBytes(inputBytes,magicBytes);
                            if(debugMode) {
                                Console.WriteLine("DEBUG: comparisonResult: {0}", comparisonResult);
                            }

                            if(comparisonResult) {
                                Console.WriteLine("[!] Probable DPAPI BLOB found: {0}", currentFile);
                                //  sloppily output the signature bytes for review
                                //Console.Write("signature bytes:");
                                /*for(int i = 0; i<20; i++) {
                                    //Console.Write(inputBytes[i]);
                                    Console.Write("0x{0} ",inputBytes[i].ToString("X2"));
                                }*/
                                //Console.Write("\n");
                            }
                        }
                    }
                } catch (IOException e) {
                    // ignore the exception, probably inaccessible file
                    if(debugMode) {
                        Console.WriteLine("IO ERROR: Exception: {0}", e.Message);  
                    }
                }  catch (Exception e) {
                    if(debugMode) {
                        Console.WriteLine("ERROR: Exception: {0}", e.Message);
                    }
                }               
            }
        } catch (IOException e) {
            // ignore the exception, probably inaccessible file
            if(debugMode) {
                Console.WriteLine("IO ERROR: Exception: {0}", e.Message);  
            }
        } catch (Exception e) {
            if(debugMode) {
                Console.WriteLine("ERROR: Exception: {0}", e.Message);
            }
        }

        Console.WriteLine("[*] Filesystem processing completed.");

        Console.WriteLine("[*] Starting registry check routine");

        //RegistryKey rk = Registry.LocalMachine;
        RegistryKey rk = Registry.CurrentUser;
        RegistryKey startingPoint = rk.OpenSubKey(registrySearchPath);

        Console.WriteLine("[*] Initiating search starting at: {0}", startingPoint.ToString());

        searchRegistryFrom(startingPoint);

        Console.WriteLine("[*] Registry processing completed.");

        Console.WriteLine("[*] Done.");
    }

    public static bool ContainsBytes(byte[] source, byte[] pattern) {
        // check the parameters
        if (source == null || pattern == null || pattern.Length == 0 || source.Length < pattern.Length)
        {
            return false; 
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
                return true; 
            }
        }
        return false;
    }
    
    public static void searchRegistryFrom(RegistryKey startingPoint) {
        // we have a starting point, now we need to parse all values
        foreach(string valueName in startingPoint.GetValueNames()) {
            string tempValue = startingPoint.GetValue(valueName).ToString();
            if(tempValue.Length >= 28) {
                if(tempValue.Contains(magicBytesEncoded)) {
                    Console.WriteLine("[!] Probable registry blob found at: {0}\\{1}", startingPoint.ToString(), valueName);
                }
            }  else {
                if(debugMode) {
                    Console.WriteLine("DEBUG: Value too short, skipping");
                }
            }
        }
        // recursive execution to process all subkeys
        foreach(string subKeyName in startingPoint.GetSubKeyNames()) {
            using(RegistryKey tempKey = startingPoint.OpenSubKey(subKeyName)) {
                searchRegistryFrom(tempKey);    
            }
        }            
    }
}