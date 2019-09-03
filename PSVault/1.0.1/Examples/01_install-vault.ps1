
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
  $vaultobject = $(Get-Vault -Address $env:VAULT_ADDR -Token $env:VAULT_TOKEN)  
  set-VaultSeal -vaultobject $vaultobject


############################################################################################################################################
# Start Vault
############################################################################################################################################
  Start-VaultTask
  # Load VauLtobject 
    $Vaultstate = Invoke-RestMethod -uri $($VaultObject.uri + "sys/seal-status") -Method get
  # Auto unseal
    start-VaultautoUnseal -apiaddress $apiaddress -VaultPath $vaultpath -UnsealKeyXML $UnsealKeyXML -AESKeyFileHash $AESKeyFileHash 
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
$state = get-vaultstatus -apiaddress $APIaddress
if($state.initialized -like $false){ 
    write-warning "Vault is not initialized"; 
    Break
}
if($state.sealed -like $true){ 
    write-warning "Vault is Sealed"; 
    start-VaultautoUnseal -apiaddress $apiaddress -VaultPath $vaultpath -UnsealKeyXML $UnsealKeyXML -AESKeyFileHash $AESKeyFileHash
}

$vaultobject = $(Get-Vaultobject -Address $env:VAULT_ADDR -Token $env:VAULT_TOKEN)  
    
# Create KV version 2
    $SecretEngineName = "kv-v2-test" 
    new-VaultSecretEngine  -SecretEngineName  $SecretEngineName -vaultobject $vaultobject
# Set KV Engine configuration
    $uri = $VaultObject.uri + $SecretEngineName + "/config"
    $payload = '{
        "max_versions": 5,
        "cas_required": false
    }'
    Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $Payload   | Write-Output
       
# Get KV Engine configuration
    $uri = $VaultObject.uri + $SecretEngineName + "/config"
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
    $uri = $VaultObject.uri + $SecretEngineName + "/data/" + $secretPath
    Invoke-RestMethod -Uri $uri -Method Delete -Headers $VaultObject.auth_header

# delete Version Secret
    $payload = '{
        "versions": [1, 2, 3, 4, 5]
    }'
    $uri = $VaultObject.uri + $SecretEngineName + "/destroy/" + $secretPath
    Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
# List versions
    $uri = $VaultObject.uri + $SecretEngineName + "/metadata/" + $secretPath
    $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    $result.data.versions
    
# delete metadata and all versions   
    $uri = $VaultObject.uri + $SecretEngineName + "/metadata/" + $secretPath
    Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header 
