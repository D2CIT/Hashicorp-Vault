# PSVault
PowerShell module for using HashiCorp Vault on windows

* [Blog Post : HashiCorp Vault on Windows with PowerShell](https://d2c-it.nl/2019/03/27/hashicorp-vault-on-windows-with-powershell/)
 
This PowerShell module can be used for installing, configuring and managing HashiCorp Vault.
It works at the moment through the vault.exe and with the vault api.

This Module contains cmdlets for install, configure and managing Hashicorp vault via PowerShell
See the Folder Examples.

import-module "C:\Program Files\WindowsPowerShell\Modules\PSVault\1.0.1\PSVault.psm1" -Verbose
get-command -Module PSVault


#### Functions for downloading and unziping software from HashiCorp
* Get-Unzip
* Get-DownloadAndUnzip
* Get-FileFromInternet
* Add-Path
* Remove-StringSpecialCharacter 

#### Functions for password and encryption                          
* Convertfrom-SecureHashAES          
* Convert-PlainpasswordtoSecurestring
* Convertto-SecureHashAES            
* Get-AESHash                       
* New-AESHASH                        
* New-AESKey                          
                                                      
#### Functions for Vault 
* Connect-Vault             
* Start-VaultWeb            
* Start-VaultTask           
* Start-VaultInit           
* start-VaultautoUnseal     
* Start-Vault               
* set-VaultUnseal           
* set-VaultSecret           
* set-VaultSeal             
* Set-VaultPowershellProfile
* set-VaultLDAP             
* Stop-VaultTask            
* set-vaultconfig           
* Remove-vaultauto          
* Remove-Vault              
* new-VaultSecretEngine     
* New-VaultPolicy           
* Install-Vault             
* get-VaultStatuscode       
* Get-VaultStatus           
* get-VaultSecretEngine     
* get-VaultSecret           
* get-Vaultobject           
* remove-VaultSecretEngine  
* Update-Vault              

#### Test function
* Import-PSVaultModule 


#### Unblock ps1 files in psvault module  after download
```
$Path  = "C:\Program Files\WindowsPowerShell\Modules\psvault" ;
$files =  get-childitem -path $Path -recurse | where {$_.Attributes -eq "Archive" } ;
foreach($file in $files){ 
 write-host " - Unblock $($file.FullName)" ; 
 Unblock-File -Path  $file.FullName 
}#EndForeach
```
