Get-Content -Path "C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SID\$GUID" -Encoding Byte -ReadCount 0 | ForEach-Object { "{0:X2}" -f $_ }
