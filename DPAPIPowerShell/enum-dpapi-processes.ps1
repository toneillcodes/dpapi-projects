Get-Process | Where-Object {$_.Modules | Where-Object {$_.ModuleName -like "*crypt32.dll*"}}
