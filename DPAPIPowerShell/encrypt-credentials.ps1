[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$File,
    [Parameter(Mandatory=$false)]
    [string]$Format,    
    [Parameter(Mandatory=$false)]
    [string]$UseGetCred
)

Write-Host "[*] DPAPI Blob Generator"

Write-Host "[*] Prompting for secret..."
# Prompt for credential data
if($UseGetCred) {
    $credential = Get-Credential
} else {
    $credential = Read-Host -Prompt "Enter secret to encrypt"
}

try {
    $protected = ConvertTo-SecureString -AsPlainText -Force -String $credential
} catch {
    Write-Error "[!] Unable to execute 'ConvertTo-SecureString', error occurred: $($_.Exception.Message)"
}

# Export to the output file
if($credential) {
    if($Format -eq "xml") {
        # Export to XML
        $protected | Export-CliXml -Path $File
    } else {
        $protected | ConvertFrom-SecureString | Out-File -FilePath $File
    }
    Write-Host "[*] DPAPI XML blob written to $File."
} else {
    Write-Error "[!] Credential value is empty, check inputs."
}

Write-Host "[*] Done."
