
############################################################################################################################################
# install Vault
############################################################################################################################################

# download Vault only
  set-DemoInstallVault -downloadManual $true -setupfolder c:\vault\download

# install vault from with downloaded zipfile
  set-DemoInstallVault -Rootpath "c:" -NoInternet $true -setupfolder c:\vault\download
  #
  set-DemoInstallVault -Rootpath "c:" -EnableLDAP $false -ldapdomain "lab.it" -NoInternet $true -setupfolder c:\vault\download

# install vault with internet connection
  set-DemoInstallVault -Rootpath "c:" -Vaultversion "1.2.2"

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
  cd c:\
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
