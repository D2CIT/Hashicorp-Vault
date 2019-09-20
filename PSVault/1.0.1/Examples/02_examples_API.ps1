    
    ############################################################################# 
    # VAULT State (initialize & seal
    #############################################################################
    
    $vaultpath = "C:\vault"

    # open scheduled task
        & c:\windows\system32\taskschd.msc /s
    
       # Load VauLtobject
        $vaultobject = Get-Vaultobject -Address "http://127.0.0.1:8200" -Token "s.lr7ShUnNu00uVGXb1iQwLXFB"  # example token.
    
    # Unseal Vault if Sealed
        $vaultstatus = get-vaultstatus -VaultObject $vaultobject
        if($vaultstatus.sealed -like $true) {
            write-host  "[vault] : Sealed."
            write-host  "[vault] : start unseal!"
            auto-VaultUnseal -vaultobject $vaultobject -VaultPath $vaultpath
          
        }else{
            write-host  "[vault] : unsealed." -for green
        }#endIf
    
    # Seal Vault
        set-VaultSeal -vaultobject $vaultobject 
    
    
    # check status
        get-vaultStatus -Vaultobject $vaultobject
    
    
    #SECRETSENGINE
    # Create KV version 1 (not working, will be fixed)
        #$SecretEngineName = "kv-v1-Cloud" 
        #new-VaultSecretEngine -vaultobject $vaultobject -SecretEngineName $SecretEngineName -KV_version 1  
    
    # Create KV version 2
        $SecretEngineName = "kv-v2-Cloud" 
        new-VaultSecretEngine -vaultobject $vaultobject -SecretEngineName $SecretEngineName -KV_version 2
    
    # Get KV Engine configuration
        $uri = $VaultObject.uri + $SecretEngineName + "/config"
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header  | Write-Output
    
    # Set KV Engine configuration
        $payload = '{
          "max_versions": 5,
          "cas_required": false
        }'
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $Payload   
    
    # Remove KV
        remove-VaultSecretEngine -vaultobject $vaultobject -SecretEngineName $SecretEngineName 
    
    
    
    #SECRET 
    # Create /overwrite secret in SecretEngine
        $SecretEngineName = "kv-v2-Cloud" 
        $secretPath       = "vsphere_api/admin"
        set-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath  -username  "admin_cloud" -password "Z33rgG3H31m12!!!!" -environment "test" -tag "testtag"
    
        $secretPath       = "vsphere_api/read"
        set-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath  -username  "reader_cloud" -password "Z33rG3H31m12!" -environment "test" -tag "testtag"
    
    
    # get Secret
        $cred = get-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath 
        $cred
    
    # delete Secret
        $uri = $VaultObject.uri + "/v1/" + $SecretEngineName + "/data/" + $secretPath
        Write-Debug $uri
        Invoke-RestMethod -Uri $uri -Method Delete -Headers $VaultObject.auth_header | Write-Output
    # delete Version Secret
        $payload = '{
            "versions": [1, 2, 3, 4, 5]
        }'
        $uri = $VaultObject.uri + "/v1/" + $SecretEngineName + "/destroy/" + $secretPath
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
    # List versions
        $uri = $VaultObject.uri + "/v1/" + $SecretEngineName + "/metadata/" + $secretPath
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.data.versions
    
    # delete metadata and all versions   
        $uri = $VaultObject.uri + "/v1/" + $SecretEngineName + "/metadata/" + $secretPath
        Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header 
    
    #region SYS examples
    
    # Audit 
        $uri = $VaultObject.uri + "/v1/sys/audit" 
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header  
    # Audit Enable     
        $payload = '{
            "type": "file",
            "options": {
                "file_path": "C:/vault/data/Vault_audit.log"
            }
        }' 
    
        $uri = $VaultObject.uri + "/v1/sys/audit/example-audit" 
        Invoke-RestMethod -Uri $uri -Method Put -Headers $VaultObject.auth_header -body $payload
    # Audit disable      
        $uri = $VaultObject.uri + "/v1/sys/audit/example-audit" 
        Invoke-RestMethod -Uri $uri -Method Delete -Headers $VaultObject.auth_header
    
    # UI Headers
        $uri = $VaultObject.uri + "/v1sys/config/ui/headers/X-Custom-Header" 
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        $payload = '{
          "values": ["custom value 1", "custom value 2"]
        } '
        $uri = $VaultObject.uri + "/v1/sys/config/ui/headers/X-Custom-Header" 
        Invoke-RestMethod -Uri $uri -Method put -Headers $VaultObject.auth_header -Body $payload
    
        $uri = $VaultObject.uri + "/v1/sys/config/ui/headers/X-Custom-Header" 
        Invoke-RestMethod -Uri $uri -Method Delete -Headers $VaultObject.auth_header
    
    # Root Generation Progress
        $uri = $VaultObject.uri + "/v1/sys/generate-root/attempt" 
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        $uri = $VaultObject.uri + "/v1/sys/generate-root/attempt" 
        Invoke-RestMethod -Uri $uri -Method put -Headers $VaultObject.auth_header
      
        $uri = $VaultObject.uri + "/v1/sys/generate-root/attempt" 
        Invoke-RestMethod -Uri $uri -Method Delete -Headers $VaultObject.auth_header
    
    # Health Information
        $uri = $VaultObject.uri + "/v1/sys/health" 
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
    # Internal UI Mounts
        $uri = $VaultObject.uri + "/v1/sys/internal/specs/openapi" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.openapi
        $result.info
        $result.paths
    
    
        $uri = $VaultObject.uri + "/v1/sys/internal/ui/mounts" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.data
        $result.data.auth  
            $result.data.auth.'approle/'
            $result.data.auth.'token/'
        $result.data.secret
    
    # Key Status
        $uri = $VaultObject.uri + "/v1/sys/key-status" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.data
    
    # Leader (endpoint is used to check the high availability status and current leader of Vault.)
        $uri = $VaultObject.uri + "/v1/sys/leader" 
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        
    # metrics (endpoint is used to get telemetry metrics for Vault.)
        $uri = $VaultObject.uri + "/v1/sys/metrics" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.Gauges
        $result.Samples | format-table
       
    # plugins catalog (endpoint is used to read, register, update, and remove plugins in Vault's catalog. Plugins must be registered before use, and once registered backends can use the plugin by querying the catalog.)
        $uri = $VaultObject.uri + "/v1/sys/plugins/catalog" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        $result.data.auth
        $result.data.database
        $result.data.secret
    
    
        $uri = $VaultObject.uri + "/v1/sys/plugins/catalog/secret/aws" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.data
        
        #register
        $uri = $VaultObject.uri + "/v1/sys/plugins/catalog/auth/ad" 
        $uri = $VaultObject.uri + "/v1/sys/plugins/catalog/database/postgresql-database-plugin" 
        $uri = $VaultObject.uri + "/v1/sys/plugins/catalog/secret/kv" 
    
    
    # policy (endpoint is used to manage ACL policies in Vault.)
        #List
        $uri = $VaultObject.uri + "/v1/sys/policy" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.keys
        $result.policies
        $result.data
        $result.data.keys
        $result.data.policies
    
        #read
        $uri = $VaultObject.uri + "/v1/sys/policy/vault_admin" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result.name
    
        $result.rules
        $result.data
        $result.data.name
        $result.data.rules
    
        #create
        
        #Create policy
        $uri  = $VaultObject.uri + "/v1/sys/policies/acl/admin"
        $AdminPolicy =  '{
          "policy": "# Manage auth methods broadly across Vault\npath \"auth/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n\n# Create, update, and delete auth methods\npath \"sys/auth/*\"\n{\n  capabilities = [\"create\", \"update\", \"delete\", \"sudo\"]\n}\n\n# List auth methods\npath \"sys/auth\"\n{\n  capabilities = [\"read\"]\n}\n\n# List existing policies\npath \"sys/policies/acl\"\n{\n  capabilities = [\"read\"]\n}\n\n# Create and manage ACL policies \npath \"sys/policies/acl/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n\n# List, create, update, and delete key/value secrets\npath \"secret/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n\n# Manage secret engines\npath \"sys/mounts/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n\n# List existing secret engines.\npath \"sys/mounts\"\n{\n  capabilities = [\"read\"]\n}\n\n# Read health checks\npath \"sys/health\"\n{\n  capabilities = [\"read\", \"sudo\"]\n}"
        }
        '
        $ProvisionerPolicy =  '{
          "policy": "# Manage auth methods broadly across Vault\npath \"auth/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n\n# Create, update, and delete auth methods\npath \"sys/auth/*\"\n{\n  capabilities = [\"create\", \"update\", \"delete\", \"sudo\"]\n}\n\n# List auth methods\npath \"sys/auth\"\n{\n  capabilities = [\"read\"]\n}\n\n# List existing policies\npath \"sys/policies/acl\"\n{\n  capabilities = [\"read\"]\n}\n\n# Create and manage ACL policies via API & UI\npath \"sys/policies/acl/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}\n\n# List, create, update, and delete key/value secrets\npath \"secret/*\"\n{\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}"
        }'

        Invoke-RestMethod -uri $uri  `
                          -headers $($vaultObject.auth_header) `
                          -Method post `
                          -body $AdminPolicy 
    
        $uri = $VaultObject.uri + "/v1/sys/policy/cloudcontrol" 
        $payload = '{}'
        $result = Invoke-RestMethod -Uri $uri -Method Put -Headers $VaultObject.auth_header -Body $payload
        $result.name
    
        #List policies
        $uri = $VaultObject.uri + "/v1/sys/policy" 
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $policies = $result.policies
    
        #read policie
        $Pol = $policies[0]
        $uri = $VaultObject.uri + "/v1/sys/policies/acl/$pol"
        $result = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        #Create/Update ACL Policy
        $Policy_name = $policies[1]
        $uri         = $VaultObject.uri + "/v1/sys/policies/acl/$Policy_name"   
        $result      = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        #Delete ACL Policy
        $Policy_name = $policies[0]
        $uri         = $VaultObject.uri + "/v1/sys/policies/acl/$Policy_name"
        $result      = Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
    # The /sys/raw endpoint is used to access the raw underlying store in Vault.
        $uri         = $VaultObject.uri + "/v1/raw/$SecretEngineName" 
        $result      = Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
        $uri         = $VaultObject.uri + "/v1/raw/logical" 
        $result      = Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
    # The /sys/rekey endpoints are used to rekey the unseal keys for Vault.
        $uri         = $VaultObject.uri + "/v1/sys/rekey/init" 
        $result      = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        $payload = '{
          "secret_shares": 10,
          "secret_threshold": 5
        }'
    
        $uri         = $VaultObject.uri + "/v1/sys/rekey/init" 
        $result      = Invoke-RestMethod -Uri $uri -Method put -Headers $VaultObject.auth_header -Body $payload
        $result.nonce
        
        #Cancel ReyKey
       $uri         = $VaultObject.uri + "/v1/sys/rekey/init" 
        $result      = Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header 
    
        #Read Backup Key
        $uri         = $VaultObject.uri + "/v1/sys/rekey/backup" 
        $result      = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header 
    
        #delete Backup Key
        $uri         = $VaultObject.uri + "/v1/sys/rekey/backup" 
        $result      = Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
    
        #Submit Key
        $uri         = $VaultObject.uri + "/v1/sys/rekey/update" 
        $payload = '{
          "key": "AB32...",
          "nonce": "abcd1234..."
        }'
        $result      = Invoke-RestMethod -Uri $uri -Method put -Headers $VaultObject.auth_header   
    
    
        #Read Rekey Verification Progress 
        $uri         = $VaultObject.uri + "/v1/sys/rekey/verify" 
        $result      = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $result 
    
        #Cancel Rekey Verification
        $uri         = $VaultObject.uri + "/v1/sys/rekey/verify" 
        $result      = Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
        $result 
    
    
        $uri         = $VaultObject.uri + "/v1/sys/rekey-recovery-key/init" 
        $result      = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
    
    # The /sys/rotate endpoint is used to rotate the encryption key.
        $uri         = $VaultObject.uri + "/v1/sys/rotate" 
        Invoke-RestMethod -Uri $uri -Method put -Headers $VaultObject.auth_header 
     
    # The /sys/step-down endpoint causes the node to give up active status.
        $uri         = $VaultObject.uri + "/v1/sys/step-down" 
        Invoke-RestMethod -Uri $uri -Method put -Headers $VaultObject.auth_header 
        
    # The /sys/tools endpoints are a general set of tools.
        $uri         = $VaultObject.uri + "/v1/sys/tools/random/164" 
        $Payload = '{
          "format": "hex"
        }'
        $result = Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -Body  $payload  
        $result.data
    
        #Hash data
        $uri         = $VaultObject.uri + "sys/tools/hash/sha2-512" 
        $Payload = '{
          "input": "adba32=="
        }'
        $result2 = Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -Body  $payload  
        $result1.data
        $result2.data
    
    
    # The /sys/wrapping/lookup endpoint returns wrapping token properties.
        $uri     = $VaultObject.uri + "/v1/sys/wrapping/lookup" 
        $TokenID = 12345
        $Payload = "{
          `"token`": `"$TokenID`"
        }"
        $result = Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -Body  $payload  
        $result.data
    
    
    #endregion
      
    #region LDAP Examples
    #Create LDAP Connection
        $uri = "http://127.0.0.1:8200/v1/auth/ldap/config"
        $payload = "{  
             `"binddn`"                       : `"`" , 
             `"case_sensitive_names`"         : false,
             `"certificate`"                  : `"`" ,
             `"deny_null_bind`"               : true,
             `"discoverdn`"                   : false,
             `"groupattr`"                    : `"cn`",
             `"groupdn`"                      : `"dc=lab,dc=it`",
             `"groupfilter`"                  : `"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))`",
             `"insecure_tls`"                 : false,
             `"tls_max_version`"              : `"tls12`",
             `"tls_min_version`"              : `"tls12`",
             `"token_explicit_max_ttl`"       : `"0`",
             `"token_max_ttl`"                : `"0`",
             `"token_no_default_policy`"      : false,
             `"token_num_uses`"               : `"0`",
             `"token_period`"                 : `"0`",
             `"token_policies`"               : `"{}`",
             `"token_ttl`"                    : `"0`",
             `"token_type`"                   : `"default`",
             `"upndomain`"                    : `"lab.it`",
             `"url`"                          : `"ldap://lab.it:389`",
             `"use_pre111_group_cn_behavior`" : false,
             `"use_token_groups`"             : false,
             `"userattr`"                     : `"samaccountname`",
             `"userdn`"                       : `"dc=lab,dc=it`" ,
             `"token_policies`"               : `"{}`" 

        }"
        #`"token_bound_cidrs`"            : `"{}`"  --> is not working 

        $result       = Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
        $LDAPSettings = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $LDAPSettings 


        $result = Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
        $result.data.versions
    
        $uri = $VaultObject.uri + "/v1/auth/ldap/config"
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        #List LDAP group
        $uri = $VaultObject.uri + "/v1/auth/ldap/groups/admins"
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        #Create LDAP Group
        $uri = $VaultObject.uri + "/v1/auth/ldap/groups/admins"
        $payload = "{
            `"policies`": `"admin,default`"
        } "
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
        #Delete LDAP Group
        $uri = $VaultObject.uri + "/v1/auth/ldap/groups/admins"
        Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
        #List LDAP Users
        $uri = $VaultObject.uri + "/v1/auth/ldap/users"
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
    
        #create/update LDAP user
        $uri = $VaultObject.uri + "/v1/auth/ldap/users/$username"
        $payload = "{
            `"policies`": `"admin,default`"
        } "
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -Body $body
    
        #delete LDAP user
        $uri = $VaultObject.uri + "/v1/auth/ldap/users/$username"
        Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
        #login ldap user
        $uri = $VaultObject.uri + "/v1/auth/ldap/users/$username"
        $payload = "{
            `"password`": `"$Password`"
        } "
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -Body $body
    #endregion
    
    
    
    
    #username password
        #Create
        $username = "MyUsername"
        $Password = Read-host "New Password"
        $uri = $VaultObject.uri + "/v1/auth/userpass/users/$username"
        $payload = "{
          `"username`": `"$username`" ,
          `"password`": `"$Password`",
          `"policies`": `"admin,default`",
          `"bound_cidrs`": [`"127.0.0.1/32`", `"128.252.0.0/16`"] ,
          `"ttl`": `"30`" ,
          `"max_ttl`": `"60`"
        }"
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
        #Read
        $uri = $VaultObject.uri + "/v1/auth/userpass/users/$username"
        $user = Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header
        $user.data
    
        #Delete
        $uri = $VaultObject.uri + "/v1/auth/userpass/users/$username"
        Invoke-RestMethod -Uri $uri -Method delete -Headers $VaultObject.auth_header
    
        #Update Password
        $uri = $VaultObject.uri + "/v1/auth/userpass/users/$username"
        $Password = read-host -Prompt "Password"
        $payload = "{
          `"password`": `"$Password`"
        }"
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
        #Update Policies on User
        $uri = $VaultObject.uri + "/v1/auth/userpass/users/$username/policies"
    
        $payload = "{
          `"policies`": [`"admin`", `"default`"]
        }"
        Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
    
        #list
        $uri = $VaultObject.uri + "/v1/auth/userpass/users"
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header 
    
        #login
        $uri = $VaultObject.uri + "/v1/auth/userpass/login/$username"
        $payload = "{
          `"password`": `"$(read-host -Prompt "Password")`"
        }"
        $login = Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
        $login.auth
    
        #list
        $uri = $VaultObject.uri + "/v1/auth/token/lookup"
        $uri = $VaultObject.uri + "/v1/auth/token/accessors"
        Invoke-RestMethod -Uri $uri -Headers $VaultObject.auth_header -Method post
    
        $uri = $VaultObject.uri + "/v1/auth/token/create-orphan"
    $payload = '{
        "policies": [
            "default",
            "admin"
        ],
        "metadata": {
        "user": "root"
        },
        "ttl": "1h",
        "renewable": true
    }'
        Try{
          Invoke-RestMethod -Uri $uri -Method post -Headers $VaultObject.auth_header -body $payload
        }catch{
          $get_error = $error[0]
          $StatusCode   = $get_error.Exception.Response.StatusCode.value__
          $StatusCodeMessage =  Get-VaultStatuscode -StatusCodes $StatusCode
          $StatusCodeMessage
        } 
    
