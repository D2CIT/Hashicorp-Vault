
############################################################################################################################################
# install Vault via set-DemoInstallVault
############################################################################################################################################
#region Install Vault Demo
$vaultversion   = "1.2.4"
$DownloadFolder = "$env:USERPROFILE\downloads"
$rootpath       = "$env:ProgramFiles\Hashicorp"
$EnableLDAP     = $true
$LdapDomain     = "d2cit.it"
# download Vault only
set-DemoInstallVault -downloadManual $true -setupfolder $DownloadFolder -Vaultversion $vaultversion  

# install vault from with downloaded zipfile
set-DemoInstallVault -Rootpath $rootpath -NoInternet $true -setupfolder $DownloadFolder -Vaultversion $vaultversion 
# install vault from with downloaded zipfile and enable/configure LDAP Auth
set-DemoInstallVault -Rootpath $rootpath -EnableLDAP $EnableLDAP  -ldapdomain $LdapDomain -NoInternet $true -setupfolder $DownloadFolder -Vaultversion $vaultversion 

# install vault with internet connection
set-DemoInstallVault -Rootpath $rootpath -Vaultversion $vaultversion
#endregion

############################################################################################################################################
# install Vault Manual
############################################################################################################################################
#region Install Vault manual steps
$vaultversion   = "1.2.4"
$DownloadFolder = "$env:USERPROFILE\downloads"
$VaultPath      = "$env:ProgramFiles\Hashicorp\Vault"
$apiaddress     = "http://127.0.0.1:8200" 
$EnableLDAP     = $true
$LdapDomain     = "d2cit.it"

#run below on a host with internet connection
$DownloadUrl  = "https://releases.hashicorp.com/vault/" + $vaultVersion + "/vault_" + $vaultVersion + "_windows_amd64.zip"            
if(!(test-path $DownloadFolder)){mkdir $DownloadFolder}    
$VaultZip     = "$DownloadFolder\vault_$($vaultversion)_windows_amd64.zip"
Get-FileFromInternet -url $DownloadUrl -outputfile $VaultZip 
break

install-Vault -VaultPath $VaultPath -Vaultversion $vaultversion  -vaultzip "$DownloadFolder\vault_$($vaultversion)_windows_amd64.zip"

$State = start-vault -vaultpath $vaultpath -APIaddress $apiAddress -ReturnState 

#Initialize Vault
if($state.Initialized -like $false){
  start-VaultInit -apiaddress $APIaddress  -VaultPath $vaultpath -Secure $true -ExportXML
}

#--------------------------------------------------------
# Secure AES key with personal HASH (Powershell)
#--------------------------------------------------------
# Enrcypt aeskey with current windows credentials and remove.
  if( (test-path "$VaultPath\config\AESkey.txt")) {
      New-AESHASH -VaultPath $VaultPath -AESKeyFile "$VaultPath\config\AESkey.txt" -AESKeyFileHash "$VaultPath\config\AESTokenHash.txt"
      if( (test-path "$VaultPath\config\AESkey.txt") -and (test-path "$VaultPath\config\AESTokenHash.txt") ){ 
          # overwrite File with empty string
            "" | out-file "$VaultPath\config\AESkey.txt"  
          # Remove empty file
            remove-item "$VaultPath\config\AESkey.txt"   
      }#EndIf
  }#EndIf

# Read encrypted keys
  Get-AESHash -VaultPath $VaultPath  -UnsealKeyXML  "$VaultPath\config\UnsealKeys.xml" -APIAddress $APIaddress -AESKeyFileHash "$VaultPath\config\AESTokenHash.txt"-Verbose

# Create Powershell profile.ps1 with variabels to login into vault.
  if( !(test-path "$env:USERPROFILE\Documents\WindowsPowerShell")){ mkdir "$env:USERPROFILE\Documents\WindowsPowerShell"}
  set-VaultPowershellProfile -VaultPath $VaultPath `
                              -ProfileFile "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1" `
                              -APIAddress $APIaddress
# Reload Profile
  . "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1" 

# Unseal Vault
  start-VaultautoUnseal -apiaddress $apiaddress -VaultPath $vaultpath -UnsealKeyXML "$VaultPath\config\UnsealKeys.xml" -AESKeyFileHash "$VaultPath\config\AESTokenHash.txt"

# setup LDAP
  if($EnableLDAP){
      set-VaultLDAP -upndomain $LdapDomain
  }
 #endregion 

############################################################################################################################################
# Stop Vault
############################################################################################################################################
  Stop-VaultTask

# Seal Vault
  $vaultobject = $(Get-Vaultobject -Address $env:VAULT_ADDR -Token $env:VAULT_TOKEN)  
  set-VaultSeal -vaultobject $vaultobject


############################################################################################################################################
# Start Vault
############################################################################################################################################
  Start-VaultTask
  # Load VauLtobject 
    $Vaultstate = Invoke-RestMethod -uri $($VaultObject.uri + "/v1/sys/seal-status") -Method get
  # Auto unseal
    [string]$VaultPath      = "c:\vault"
    [string]$UnsealKeyXML   = "$VaultPath\config\UnsealKeys.xml"
    [string]$AESKeyFile     = "$VaultPath\config\AESTokenHash.txt"
    [string]$AESKeyFileHash = "$VaultPath\config\AESTokenHash.txt"
    [string]$modulepath     = "C:\Program Files\WindowsPowerShell\Modules\PSVault\1.0.1\PSVault.psm1"
    [string]$APIAddress     = "http://127.0.0.1:8200"
    if(!(test-path $UnsealKeyXML))  { write-warning "could not find $UnsealKeyXML"   ; break}
    if(!(test-path $AESKeyFileHash)){ write-warning "could not find $AESKeyFileHash" ; break}  
    if(!(test-path $modulepath))    { write-warning "could not find $modulepath"     ; break}  

    start-VaultautoUnseal -apiaddress $APIAddress  -VaultPath $vaultpath -UnsealKeyXML $UnsealKeyXML -AESKeyFileHash $AESKeyFileHash 
############################################################################################################################################ 
# remove Vault
############################################################################################################################################
  # set-location to C: The current location should not be the path to delete otherwise the path will be in use
  set-location c:\
  Remove-Vault -vaultpath  $vaultpath -confirm $true
  # or remove vault including powershell profile
  Remove-vaultauto -vaultpath $vaultpath

############################################################################################################################################ 
# Create Secret Engine
############################################################################################################################################
# Check State of Vault
    $state = get-vaultstatus -apiaddress $APIaddress
    if($state.initialized -like $false){ 
        write-warning "Vault is not initialized"; 
        Break
    }
    if($state.sealed -like $true){ 
        write-warning "Vault is Sealed"; 
        start-VaultautoUnseal -apiaddress $apiaddress -VaultPath $vaultpath -UnsealKeyXML $UnsealKeyXML -AESKeyFileHash $AESKeyFileHash
    } 
    

# Load Vaultobject
    $vaultobject = $(Get-Vaultobject -Address $env:VAULT_ADDR -Token $env:VAULT_TOKEN)  
    
# Create KV version 2
    $SecretEngineName = "kv-v2-test" 
    new-VaultSecretEngine  -SecretEngineName  $SecretEngineName -vaultobject $vaultobject
# Set KV Engine configuration
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri  + "/" + $SecretEngineName + "/config"
    }else{
        $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/config"
    }#endIf
    
    $payload = '{
        "max_versions": 5,
        "cas_required": false
    }'
    Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $Payload   | Write-Output
       
# Get KV Engine configuration
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri  + "/" + $SecretEngineName + "/config"
    }else{
        $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/config"
    }#endIf
    Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header  | Write-Output
    
# Remove KV
    remove-VaultSecretEngine -vaultobject $vaultobject -SecretEngineName $SecretEngineName 

# Create /overwrite secret in SecretEngine
    $secretPath  = "vsphere_api/test"
    $username    = "admintest" 
    $password    = "Z33rgG3H31m12!!!!" 
    $environment = "test" 
    $tag         = "tag"
    set-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath -username $username -password $password -environment $environment -tag $tag

# get Secret
    $cred = get-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath 
    $cred    
            
# delete Secret
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri + "/" + $SecretEngineName + "/data/" + $secretPath
    }else{
        $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/data/" + $secretPath
    }#endIf
   
    Invoke-RestMethod -Uri $uri -Method Delete -Headers $VaultObject.auth_header

# delete Version Secret
    $payload = '{
        "versions": [1, 2, 3, 4, 5]
    }'
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri + "/" + $SecretEngineName + "/destroy/" + $secretPath
    }else{
        $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/destroy/" + $secretPath
    }#endIf
    Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
# List versions
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri + "/" + $SecretEngineName + "/metadata/" + $secretPath
    }else{
        $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/metadata/" + $secretPath
    }#endIf
    $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    $result.data.versions
    
# delete metadata and all versions  
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri + "/" + $SecretEngineName + "/metadata/" + $secretPath
    }else{
        $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/metadata/" + $secretPath
    }#endIf 
    Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header 
