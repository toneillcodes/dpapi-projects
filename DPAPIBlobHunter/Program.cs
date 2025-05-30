using System.Net.NetworkInformation;
using Microsoft.Win32;

public class DPAPIBlobHunter {
    //static byte[] magicBytes = { 1, 0, 0, 0, 208, 140, 157, 223, 1, 21, 209, 17, 140, 122, 0, 192, 79, 194, 151, 235 };  
    static byte[] magicBytes = { 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB };
    static string magicBytesEncoded = "AQAAANCMnd8BFdERjHoAwE/Cl+s";
    static string registrySearchPath = "Software";

    static bool debugMode = false;
    static bool showErrors = false;
    static bool runFileSearch = false;
    static bool runRegistrySearch = false;

    public static int Main(string[] args)
    {
        bool fileProvided = false;
        string fileParam = "";
        bool regKeyProvided = false;
        string regParam = "";

        Console.WriteLine("[*] Running DPAPI Blob Hunter");

        //  argument parsing
        if (args.Length >= 1)
        {
            foreach (var arg in args)
            {
                if (arg.StartsWith("/file:"))
                {
                    Console.WriteLine("[>] File search enabled.");
                    fileProvided = true;
                    //  parse the option value
                    int separatorIndex = arg.IndexOf(':');
                    if (separatorIndex > -1)
                    {
                        string fileCmd = arg.Substring(0, separatorIndex).Trim();
                        fileParam = arg.Substring(separatorIndex + 1).Trim();
                        //Console.WriteLine($"cmd: {fileCmd}, param: {fileParam}");
                        //result.Add(new KeyValuePair<string, string>(index, value));
                    }
                }

                if (arg.StartsWith("/reg:"))
                {
                    Console.WriteLine("[>] Registry search enabled.");
                    regKeyProvided = true;
                    //  parse the option value
                    int separatorIndex = arg.IndexOf(':');
                    if (separatorIndex > -1)
                    {
                        string regCmd = arg.Substring(0, separatorIndex).Trim();
                        regParam = arg.Substring(separatorIndex + 1).Trim();
                        //Console.WriteLine($"cmd: {regCmd}, param: {regParam}");
                        //result.Add(new KeyValuePair<string, string>(index, value));
                    }
                }
            }

            //  stop processing - we don't have one of our two required fields
            if (fileProvided == false && regKeyProvided == false)
            {
                Console.WriteLine("ERROR: Either file path or registry path required!");
            }
            else
            {
                if (fileProvided)
                {
                    Console.WriteLine("[*] Starting filesystem check routine");
                    if (debugMode)
                    {
                        Console.WriteLine($"[>] Filesystem Search Base: {fileParam}");
                    }
                    searchFilesFrom(fileParam);
                }

                if (regKeyProvided)
                {
                    Console.WriteLine("[*] Starting registry check routine");
                    string registryBase = regParam.Substring(0, 4);
                    string registryPath = regParam.Substring(5, regParam.Length - 5);
                    if (debugMode)
                    {
                        Console.WriteLine($"[>] Registry Search Base: {registryBase}");
                        Console.WriteLine($"[>] Registry Search Path: {registryPath}");
                    }
                    if (registryBase == "HKLM")
                    {
#pragma warning disable CA1416 // Validate platform compatibility
                        RegistryKey rk = Registry.LocalMachine;
#pragma warning restore CA1416 // Validate platform compatibility
                        if (rk != null)
                        {
#pragma warning disable CA1416 // Validate platform compatibility
                            RegistryKey? startingPoint = rk.OpenSubKey(registryPath);
#pragma warning restore CA1416 // Validate platform compatibility
                            if (startingPoint != null)
                            {
#pragma warning disable CA1416 // Validate platform compatibility
                                Console.WriteLine("[*] Initiating search starting at: {0}", startingPoint.ToString());
#pragma warning restore CA1416 // Validate platform compatibility
                                searchRegistryFrom(startingPoint);
                            }
                            else
                            {
                                Console.WriteLine($"ERROR: Unable to open registry key, null value returned for startingPoint");
                            }
                        }
                        else
                        {
                            Console.WriteLine("ERROR: Unable to open registry key, null value returned for rk");
                        }
                    }
                    else if (registryBase == "HKCU")
                    {
#pragma warning disable CA1416 // Validate platform compatibility
                        RegistryKey rk = Registry.CurrentUser;
#pragma warning restore CA1416 // Validate platform compatibility
                        if (rk != null)
                        {
#pragma warning disable CA1416 // Validate platform compatibility
                            RegistryKey? startingPoint = rk.OpenSubKey(registryPath);
#pragma warning restore CA1416 // Validate platform compatibility
                            if (startingPoint != null)
                            {
#pragma warning disable CA1416 // Validate platform compatibility
                                Console.WriteLine("[*] Initiating search starting at: {0}", startingPoint.ToString());
#pragma warning restore CA1416 // Validate platform compatibility
                                searchRegistryFrom(startingPoint);
                            }
                            else
                            {
                                Console.WriteLine($"ERROR: Unable to open registry key, null value returned for startingPoint");
                            }
                        }
                        else
                        {
                            Console.WriteLine("ERROR: Unable to open registry key, null value returned for rk");
                        }
                    }
                    else
                    {
                        Console.WriteLine("ERROR: Unrecognized registry base, valid values: HKLM or HKCU");
                        System.Environment.Exit(-1);
                    }
                    Console.WriteLine("[*] Registry processing completed.");
                }
            }
        }
        else
        {
            Console.WriteLine("ERROR: Either file path or registry path required!");
        }

        Console.WriteLine("[*] Done.");

        return 0;
    }

    public static bool ContainsBytes(byte[] source, byte[] pattern)
    {
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

    public static void searchFilesFrom(string searchPath)
    {
        try
        {
            // https://learn.microsoft.com/en-us/dotnet/api/system.io.directory?view=net-9.0
            var enumOptions = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, ReturnSpecialDirectories = true, AttributesToSkip = FileAttributes.None };
            var fileList = Directory.EnumerateFiles(searchPath, "*", enumOptions);
            foreach (string currentFile in fileList)
            {
                string fileName = currentFile.Substring(searchPath.Length + 1);
                if(debugMode) {
                    Console.WriteLine("[DEBUG] Processing: {0}", fileName);
                }
                // FileStream byte processing based on the FileStream.Read Method reference
                try {
                    using (FileStream fs = File.OpenRead(currentFile)) {
                        if(fs.Length > Int32.MaxValue) {
                            Console.WriteLine("[>] File too large, skipping {0}",currentFile);
                        } else {
                            if(debugMode) {
                                Console.WriteLine("[DEBUG] fs.length: {0}",fs.Length);
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
                                Console.WriteLine("[DEBUG] comparisonResult: {0}", comparisonResult);
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
                    if(showErrors || debugMode) {
                        Console.WriteLine("[ERROR] IO Exception: {0}", e.Message);  
                    }
                }  catch (Exception e) {
                    if(showErrors || debugMode) {
                        Console.WriteLine("[ERROR] Exception: {0}", e.Message);
                    }
                }               
            }
        /*} catch (IOException e) {
            // ignore the exception, probably inaccessible file
            if(debugMode) {
                Console.WriteLine("IO ERROR: Exception: {0}", e.Message);  
            }*/
        } catch (Exception e) {
            if(showErrors || debugMode) {
                Console.WriteLine("[ERROR] Exception unable to enumerate file search base: {0}", e.Message);
            }
        }

        Console.WriteLine("[*] Filesystem processing completed.");
    }

    public static void searchRegistryFrom(RegistryKey startingPoint)
    {
        // we have a starting point, now we need to parse all values
#pragma warning disable CA1416 // Validate platform compatibility
        foreach (string valueName in startingPoint.GetValueNames())
        {
#pragma warning disable CA1416 // Validate platform compatibility
            string tempValue = startingPoint.GetValue(valueName).ToString();
#pragma warning restore CA1416 // Validate platform compatibility
            if (tempValue.Length >= 28)
            {
                if (tempValue.Contains(magicBytesEncoded))
                {
#pragma warning disable CA1416 // Validate platform compatibility
                    Console.WriteLine("[!] Probable registry blob found at: {0}\\{1}", startingPoint.ToString(), valueName);
#pragma warning restore CA1416 // Validate platform compatibility
                }
            }
            else
            {
                if (debugMode)
                {
                    Console.WriteLine("[DEBUG] Value too short, skipping");
                }
            }
        }
#pragma warning restore CA1416 // Validate platform compatibility
        // recursive execution to process all subkeys
#pragma warning disable CA1416 // Validate platform compatibility
        foreach (string subKeyName in startingPoint.GetSubKeyNames())
        {
#pragma warning disable CA1416 // Validate platform compatibility
            using (RegistryKey tempKey = startingPoint.OpenSubKey(subKeyName))
            {
                searchRegistryFrom(tempKey);
            }
#pragma warning restore CA1416 // Validate platform compatibility
        }
#pragma warning restore CA1416 // Validate platform compatibility
    }
}
