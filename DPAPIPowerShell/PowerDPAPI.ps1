function PowerDPAPI {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$searchPath
    )

    $fileList = Get-ChildItem -Path $searchPath -File -Force -Recurse | select-object -ExpandProperty FullName

    if($fileList) {
        foreach ($file in $fileList) {
            if($VerbosePreference) {
                Write-Host "[>] Processing file: $file"
            }

            # Number of bytes to check
            $byteCount = 1024

            # Read bytes from file
            $inputBytes = Get-Content -Path $file -Encoding Byte -TotalCount $byteCount

            # Convert byte array to hex string
            $hexInputBytes = ($inputBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""

            $magicByteIndex = $hexInputBytes.IndexOf("01000000D08C9DDF0115D1118C7A00C04FC297EB")
            if($magicByteIndex -ge 0) {
                $md5Hash = Get-FileHash -Path $file -Algorithm MD5 | Select-Object -ExpandProperty Hash
                $sha1Hash = Get-FileHash -Path $file -Algorithm SHA1 | Select-Object -ExpandProperty Hash
                $sha256Hash = Get-FileHash -Path $file -Algorithm SHA256 | Select-Object -ExpandProperty Hash

                Write-Host "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
                Write-Host "[!] Probable DPAPI blob found"
                Write-Host "[>] File: $file"
                Write-Host "[>] MD5 Hash: $md5Hash"
                Write-Host "[>] SHA-1 Hash: $sha1Hash"
                Write-Host "[>] SHA-256 Hash: $sha256Hash"
                #Write-Host "[>] inputBytes: $hexInputBytes"

                $magicByteIndex = $hexInputBytes.IndexOf("01000000D08C9DDF0115D1118C7A00C04FC297EB")
                if($VerbosePreference) {
                    Write-Host "[>] Magic Byte Index: $magicByteIndex"
                }

                # Advance the pointer to the master key GUID and extract the bytes
                $bytePointer = $magicByteIndex + 48
                $masterKeyGuid = $hexInputBytes.Substring($bytePointer, 32)
                if($VerbosePreference) {
                    Write-Host "[>] masterKeyGuid: $masterKeyGuid"
                }
                
                # Parse out the master key bytes for processing
                $guidGroup1 = $masterKeyGuid.Substring(0,8)
                $guidGroup2 = $masterKeyGuid.Substring(8,4)
                $guidGroup3 = $masterKeyGuid.Substring(12,4)
                $guidGroup4 = $masterKeyGuid.Substring(16,4)
                $guidGroup5 = $masterKeyGuid.Substring(20,12)
                
                if($VerbosePreference) {
                    Write-Host "[>] guidGroup1: $guidGroup1"
                    Write-Host "[>] guidGroup2: $guidGroup2"
                    Write-Host "[>] guidGroup3: $guidGroup3"
                    Write-Host "[>] guidGroup4: $guidGroup4"
                    Write-Host "[>] guidGroup5: $guidGroup5"
                }

                $guidGroupBytes1 = for ($i = 0; $i -lt $guidGroup1.Length; $i += 2) {
                    [Convert]::ToByte($guidGroup1.Substring($i, 2), 16)
                }

                $guidGroupBytes2 = for ($i = 0; $i -lt $guidGroup2.Length; $i += 2) {
                    [Convert]::ToByte($guidGroup2.Substring($i, 2), 16)
                }

                $guidGroupBytes3 = for ($i = 0; $i -lt $guidGroup3.Length; $i += 2) {
                    [Convert]::ToByte($guidGroup3.Substring($i, 2), 16)
                }

                $guidGroupBytes4 = for ($i = 0; $i -lt $guidGroup4.Length; $i += 2) {
                    [Convert]::ToByte($guidGroup4.Substring($i, 2), 16)
                }

                $guidGroupBytes5 = for ($i = 0; $i -lt $guidGroup5.Length; $i += 2) {
                    [Convert]::ToByte($guidGroup5.Substring($i, 2), 16)
                }

                [Array]::Reverse($guidGroupBytes1)
                [Array]::Reverse($guidGroupBytes2)
                [Array]::Reverse($guidGroupBytes3)

                $formattedGroup1 = (($guidGroupBytes1 | ForEach-Object { "{0:X2}" -f $_ }) -join "").ToLower()
                $formattedGroup2 = (($guidGroupBytes2 | ForEach-Object { "{0:X2}" -f $_ }) -join "").ToLower()
                $formattedGroup3 = (($guidGroupBytes3 | ForEach-Object { "{0:X2}" -f $_ }) -join "").ToLower()
                $formattedGroup4 = (($guidGroupBytes4 | ForEach-Object { "{0:X2}" -f $_ }) -join "").ToLower()
                $formattedGroup5 = (($guidGroupBytes5 | ForEach-Object { "{0:X2}" -f $_ }) -join "").ToLower()

                if($VerbosePreference) {
                    Write-Host "[>] formattedGroup1: $formattedGroup1"
                    Write-Host "[>] formattedGroup2: $formattedGroup2"
                    Write-Host "[>] formattedGroup3: $formattedGroup3"
                    Write-Host "[>] formattedGroup4: $formattedGroup4"
                    Write-Host "[>] formattedGroup5: $formattedGroup5"

                    # we don't actually need/use this value, but it's helpful for troubleshooting
                    [byte[]]$mkGuidValue = $guidGroup1Bytes + $guidGroupBytes2 + $guidGroupBytes3 + $guidGroupBytes4 + $guidGroupBytes5
                    Write-Host "[>] mkGuidValue: $([BitConverter]::ToString($mkGuidValue))"
                }

                $mkGuidString = $formattedGroup1 + "-" + $formattedGroup2 + "-" + $formattedGroup3 + "-" + $formattedGroup4 + "-" + $formattedGroup5
                Write-Host "[>] mkGuidString: $mkGuidString"

                # advance pointer beyond the flags that we aren't interested in
                $bytePointer = $bytePointer + 40
                # read the description length
                $inputDescriptionLen = $hexInputBytes.Substring($bytePointer, 8)
                # advance pointer to account for the bytes we just read
                $bytePointer = $bytePointer + 8
                
                $descriptionLenBytes = for ($i = 0; $i -lt $inputDescriptionLen.Length; $i += 2) {
                    [Convert]::ToByte($inputDescriptionLen.Substring($i, 2), 16)
                }

                if($VerbosePreference) {
                    Write-Host "[>] descriptionLen: $inputDescriptionLen"
                    Write-Host "[>] descriptionLenBytes: $([BitConverter]::ToString($descriptionLenBytes))"
                }

                # convert to integer for use in the following SubString method call
                $szDescriptionLen = [BitConverter]::ToInt32($descriptionLenBytes, 0)
                if($VerbosePreference) {
                    Write-Host "[>] szDescriptionLen: $szDescriptionLen"
                }

                # Parse the bytes for the description string
                $szDescription = $hexInputBytes.Substring($bytePointer, $szDescriptionLen * 2)
                if($VerbosePreference) {
                    Write-Host "[>] szDescription: $szDescription"
                }

                # Convert the hex bytes to ASCII character codes
                $descriptionString = ""
                for ($i = 0; $i -lt $szDescription.Length; $i += 2) {
                    $twoDigitHex = $szDescription.Substring($i, 2)
                    $descriptionString += [char][Convert]::ToInt32($twoDigitHex, 16)
                }
                Write-Host "[>] descriptionString: $descriptionString"

                # process complete file bytes for output to stdout
                $fullBlobFile = (Get-Content -Path $file -Encoding Byte -ReadCount 0 | ForEach-Object { "{0:X2}" -f $_ }).Replace(" ", "")
                # convert to byte array
                $blobFileByteArray = for ($i = 0; $i -lt $fullBlobFile.Length; $i += 2) {
                    [Convert]::ToByte($fullBlobFile.Substring($i, 2), 16)
                }
                # format bytes to include '\x' prefix
                $blobOutput = $blobFileByteArray | ForEach-Object { '\x{0:X2}' -f $_ }
                # write bytes to stdout
                Write-Host "-------------- START blob output --------------"
                $blobOutput -join ''
                Write-Host "--------------  EOF blob output  --------------"

                Write-Host "[>] Locating corresponding master key file"

                $protectDirectory = $Env:AppData + "\Microsoft\Protect"
                $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                if($userSid) {
                    $mkDirectory = $protectDirectory + "\" + $userSid
                    $mkFilePath = $mkDirectory + "\" + $mkGuidString
                    
                    if($VerbosePreference) {
                        Write-Host "[>] Master Key Directory: " $mkDirectory
                    }

                    Write-Host "[>] mkFilePath: $mkFilePath"

                    if(Test-Path $mkFilePath) {
                        # file bytes
                        $fullMkFile = (Get-Content -Path $mkFilePath -Encoding Byte -ReadCount 0 | ForEach-Object { "{0:X2}" -f $_ }).Replace(" ", "")
                        # convert to byte array
                        $mkFileByteArray = for ($i = 0; $i -lt $fullMkFile.Length; $i += 2) {
                            [Convert]::ToByte($fullMkFile.Substring($i, 2), 16)
                        }
                        # format bytes to include '\x' prefix
                        $mkOutput = $mkFileByteArray | ForEach-Object { '\x{0:X2}' -f $_ }
                        # write bytes to stdout
                        Write-Host "-------------- START master key --------------"
                        $mkOutput  -join ''
                        Write-Host "--------------  EOF master key  --------------"
                    } else {
                        Write-Host "[>] Corresponding master key file not found at: $mkFilePath"
                    }
                    Write-Host "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
                    #>                    
                } else {
                    Write-Host "[ERROR] Unable to determine user SID"
                }
            } else {
                # output nothing for files that don't have a match
                if($VerbosePreference) {
                    Write-Host "[>] No DPAPI blob within the first $byteCount bytes"
                }
            }    
        }
    } else {
        Write-Host "[>] No files found."
    }
    Write-Host "[*] Done."
}
