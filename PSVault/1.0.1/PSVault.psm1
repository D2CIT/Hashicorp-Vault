
##############################################################################
# Main Function
##############################################################################
Function Get-Unzip                           {
    <#
     .Synopsis
         get-Unzip
     .DESCRIPTION
        get-Unzip
     .EXAMPLE     
        get-Unzip -zipfile "C:\temp\filename.zip" 
      .EXAMPLE          
        get-Unzip -zipfile "C:\temp\filename.zip" -unzippath "c:\temp\filename" 
     .EXAMPLE 
        get-Unzip -zipfile "C:\temp\filename.zip" -verbose

        VERBOSE: Folder "C:\temp\filename"  already exists
        VERBOSE: [unzip]        : Overwrite is set to true.
        VERBOSE: [unzip]        : "C:\temp\filename.zip\consul.exe"
        VERBOSE: [unzip]        : unzip is completed
        VERBOSE: [unzip]        : path is C:\temp\filename

        overwrite       : True
        files           : {testfile1.txt}
        sourcefile      : C:\temp\filename.zip
        destinationpath : C:\temp\filename
        count           : 1
        status          : completed
    #>    
  
    [CmdletBinding()]  
 
    param(
        [Parameter(Mandatory=$true)]
        [string]$zipfile , 
        [Parameter(Mandatory=$false)]
        [string]$unzipPath = "$env:USERPROFILE\Downloads\"+ $(($zipfile.split("\")[-1]) -replace(".zip",""))  ,
        [boolean]$overwrite = $true ,
        [switch]$NoOutput
    )
    
    begin{
        $shell    = New-Object -ComObject shell.application
        if(!(test-path $unzipPath)){
            write-verbose "Create folder $unzipPath"
            mkdir $unzipPath 
        }else{
            write-verbose "Folder $unzipPath already exists"
        }#EndIf
    }    
    process{
        #Add-Type -AssemblyName System.IO.Compression.FileSystem
        #[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
       
        $FileHash = [ordered]@{}
        $zip = $shell.NameSpace($zipfile)
        foreach ($item in $zip.items()) {
            $status = "completed"

                $FileToUnzip = $($unzipPath + "\" + $(($item.path).split("\")[-1]))
                $FileHash.add($(($item.path).split("\")[-1]),$FileToUnzip)
                if(test-path $FileToUnzip){
                    if($overwrite -like $true){
                        write-verbose "[unzip]`t: Overwrite is set to true."
                        remove-item $FileToUnzip -Force
                    }#EndIf 
                }#EndIf  
                #unzip file
                write-verbose "[unzip]`t: $($item.path)"   
                try{        
                    $shell.Namespace("$unzipPath").CopyHere($item) 
                }catch{
                    $status = "Failed"
                }#EndTryCatch
        } #Endforeach   
    }
    end{
        
        write-verbose "[unzip]`t: unzip is $status"
        write-verbose "[unzip]`t: path is $unzipPath"
        If($NoOutput){
            write-verbose "[unzip]`t: No output is selected" 
        }else{
            new-object -TypeName psobject -Property @{
                sourcefile      = $zipfile
                destinationpath = $unzipPath
                status          = $status
                files           = $FileHash
                count           = $FileHash.count
                overwrite       = $overwrite
            }#EndNewObject
        }#EndIf
    }
} #EndFunction
Function Get-DownloadAndUnzip                {
    <#
     .Synopsis
        get-DownloadAndUnzip
     .DESCRIPTION
        get-DownloadAndUnzip will download and unzip the file
        needed function 
         - get-Unzip
         - get-FileFromInternet
      .EXAMPLE     
        get-DownloadAndUnzip -DownloadUrl "https://releases.hashicorp.com/vault/1.0.2/vault_1.0.2_windows_amd64.zip" 
        
        files will be
         - downloaded to the download folder of the current user
         - unzipped to the default path : C:\Users\xxxxxxxxxxxxxxxxxxxx\Downloads\vault_1.0.2_windows_amd64
     .EXAMPLE     
        get-DownloadAndUnzip -DownloadUrl "https://releases.hashicorp.com/vault/1.0.2/vault_1.0.2_windows_amd64.zip" `
                            -UnzipPath "C:\windows\system32\WindowsPowerShell\v1.0"
    #>    
  
    [CmdletBinding()]  
 

    param(
        [Parameter(Mandatory=$true)]       
        [string]$DownloadUrl , 
        [Parameter(Mandatory=$false)]    
        [string]$unzipPath
    )

    begin{
        #Check if needed functions are loaded
        if (!(Get-Command get-Unzip -errorAction SilentlyContinue)){write-warning "could not find get-Unzip. Script will abort"; break}
        if (!(Get-Command get-FileFromInternet -errorAction SilentlyContinue)){write-warning "could not find get-FileFromInternet. Script will abort"; break}
    }

    process{
        
        $download = get-FileFromInternet -url $DownloadUrl
        if($download.status -like "completed"){
            if(test-path $download.destination){
                if($unzipPath -notlike ""){
                    $unzip = get-Unzip -zipfile $download.destination -unzipPath $unzipPath
                }else{
                    $unzip = get-Unzip -zipfile $download.destination
                } #EndIf  
            }else{
                Write-warning "Could not find zip file $($download.destination)"
            }#EndIf
        }#endIf

        write-verbose "URL           : $DownloadUrl"
        write-verbose "Download      : $($download.status)"        
        write-verbose "Unzip         : $($unzip.status)"
        write-verbose "UnzippedFiles : $($unzip.count)"

    }

    end{
        return $unzip
    }

} #EndFunction
Function Get-FileFromInternet                {
    <#
     .Synopsis
        get-FileFromInternet
     .DESCRIPTION
        get-FileFromInternet wil download a file form the internet. Default download directory is the downloads folder in the user profile ($env:USERPROFILE\Downloads)
    .EXAMPLE 
        get-FileFromInternet -url "https://releases.hashicorp.com/vault/1.0.2/vault_1.0.2_windows_amd64.zip"   
        
        destination       : C:\Users\xxxxxxxxxxxxxxx\Downloads\consul_1.4.0_windows_amd64.zip
        status            : completed
        source            : https://releases.hashicorp.com/consul/1.4.0/consul_1.4.0_windows_amd64.zip
        DownloadTime(Sec) : 3
        note              : Download completed

     .EXAMPLE     
        $URL        = "https://releases.hashicorp.com/vault/1.0.2/vault_1.0.2_windows_amd64.zip"
        $outputfile = "$env:USERPROFILE\documents\hashicorp\$($url.split("/")[-1])"
        get-FileFromInternet -url $URL -outputfile $outputfile -verbose     
     .EXAMPLE 
        get-FileFromInternet -url "https://releases.hashicorp.com/vault/1.0.2/vault_1.0.2_windows_amd64.zip" -verbose -NoOutput
    #>

    [CmdletBinding()] 
 
    param(
        [Parameter(Mandatory=$true)]
        [string]$url = "https://github.com/git-for-windows/git/releases/download/v2.20.1.windows.1/Git-2.20.1-64-bit.exe" ,
        [Parameter(Mandatory=$false)] 
        [string]$outputfile = "$env:USERPROFILE\Downloads\$($url.split("/")[-1])",
        [switch]$NoOutput 
    )

    begin{
        Import-Module BitsTransfer
    }

    Process {
        try{            
            
            Write-Verbose "[progress]`t: start Download " 
            Write-Verbose "`t`t: source      = $url"
            Write-Verbose "`t`t: destination = $outputfile " 
           
            $start_time = Get-Date
            Start-BitsTransfer -Source $url -Destination $outputfile  -ErrorAction Stop            
 
            if(test-path $outputfile ){                
                $status = "completed"
                $note   = "Download $status"   
            }else{
                Write-warning "Could not find downloaded file!!"
                $status = "failed" 
                $note   = "Download $status : Could not find downloaded file"
            }#endIf
            $Downloadtime = $((Get-Date).Subtract($start_time).Seconds)
        
        }catch{
            write-warning "Error downloading file!"     
            $status = "failed"
            $note   = "Download $status : $($error[0].Exception )"
        }#endTryCatch
        #Verbose
        write-Verbose "[progress]`t: $note  !!"
        Write-Verbose "[finished]`t: $((Get-Date).Subtract($start_time).Seconds) second(s)"  
        If($NoOutput){
            write-Verbose "no output"
        }else{
            $result = new-object -TypeName psobject -property @{
                source              = $Url 
                destination         = $outputfile
                status              = $Status
                note                = $note 
                "DownloadTime(Sec)" = $Downloadtime 
            }#EndNewObject
        }#endIf
    }

    end{
        #Cleanup used variables
        if($start_time){Remove-Variable -name start_time -Force}#endIf
        if($url){Remove-Variable -name url -Force}#endIf
        if($outputfile){Remove-Variable -name outputfile -Force}#endIf
        If($NoOutput){ 
        }else{
            return $result
        }#endIf   
    }

} #EndFunction
Function Add-Path                            {
    <#
        .SYNOPSIS
         PowerShell function to modify Env:Path in the registry
        .DESCRIPTION
         Includes a parameter to append the Env:Path
        .EXAMPLE
         Add-Path -NewPath "D:\Downloads"
    #>

    Param (
        [String]$NewPath ="D:\Powershell"
    )

    Begin {
        #Clear-Host
    } # End of small begin section

    Process {
        #Clear-Host
        $Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"
        $OldPath = (Get-ItemProperty -Path "$Reg" -Name PATH).Path
        if(  $oldpath.split(";") -contains "$newpath") {
            Write-host "[EnvPath] : $newpath is already added to the environment variables." -ForegroundColor green
        }else{
            $NewPath = $OldPath + ';' + $NewPath
            Set-ItemProperty -Path "$Reg" -Name PATH -Value $NewPath -Confirm:$false
        }
    } #End of Process
} #EndFunction

##############################################################################
# Password and encryption Functions
##############################################################################
Function Convert-PlainpasswordtoSecurestring {
    <#
     .Synopsis
        Convert-PLainpasswordtoSecurestring
     .DESCRIPTION
        Convert-PLainpasswordtoSecurestring
     .EXAMPLE 
       Convert-PLainpasswordtoSecurestring -token "balbalkjshiukjabjk" 
    #>

    [CmdletBinding()] 
     
    param (
        
        # Param1 help description
        [Parameter(Mandatory=$true,Position=0)]
        [Alias("password")] 
        $Token 

    )
    
    begin {
        $securestring = new-object System.Security.SecureString
        $chars        = $Token.toCharArray()
    }

    Process{
        foreach ($char in $chars) {
            $secureString.AppendChar($char)
        }
    }
   
    end{
        return  $secureString
    }
} #End Function
Function New-AESKey                          {
    <#
     .Synopsis
        New-AESKey  
     .DESCRIPTION
        New-AESKey  
     .EXAMPLE 
        New-AESKey 
     .EXAMPLE 
        New-AESKey -AESKeySize 24       
    #>

    [CmdletBinding()] 

    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet(16,24,32)]
        [int]$AESKeySize = 32
    )

    begin{}

    process{
        # Define AES KEY
          $AESKey = (New-Object Byte[] $AESKeySize)

        # Create Random AES Key in length specified in $Key variable.
          [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    }

    end{
        return $AESKey
    }

} #End Function
Function Convertto-SecureHashAES             {
    <#
     .Synopsis
        Convertto-SecureHashAES   
     .DESCRIPTION
        Convertto-SecureHashAES will convert plain text  to a hash.  
     .EXAMPLE 
         $AESKey     = new-AESKey -AESKeySize 16
         Convertto-SecureHashAES -token "ditiseensecuretoken" -tokenName "UnsealKey1" -AESKey $AESKey 
         
         Name         Hash                                                                                                                                                                                 
         ----         ----                                                                                                                                                                                 
         {UnsealKey1} 76492d1116743f0423413b16050a5345MgB8ADIATDMANA...

    #>

    [CmdletBinding()]     

    Param(
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string[]]$token ,
        [Parameter(Mandatory=$true)]
        [string[]]$tokenName ,

        # Param3 help description
        [Parameter(Mandatory=$false)]
        $AESKey
     
    )

    begin{
        if(!($AESKey)){$AESKey= new-AESKey }      
    }

    process{
        New-object -TypeName PSObject -Property @{
            AESKey = $AESkey
            Hash   = ConvertFrom-SecureString -SecureString (Convert-PLainpasswordtoSecurestring -token $token) -Key $AESKey
            Name   = $tokenName
        }
    }

    end{
        return $result
    }

} #End Function
Function Convertfrom-SecureHashAES           {
    <#
     .Synopsis
        Convertfrom-SecureHashAES   
     .DESCRIPTION
        Convertfrom-SecureHashAES will convert the hashed token back to plain text 
     .EXAMPLE 
        $AESKey      = new-AESKey -AESKeySize 16
        $HashedToken = Convertto-SecureHashAES -token "DitIsEenSecureToken" -tokenName "UnsealKey1" -AESKey $AESKey

        Convertfrom-SecureHashAES -Hash $($HashedToken.hash) -AESKey $AESKey
    #>

    [CmdletBinding()]  

    param(
        # Param help description
        [Parameter(Mandatory=$true)]
        $AESKey,
        # Param help description
        [Parameter(Mandatory=$true)]    
        $Hashtoken 
    )

    begin{}

    process{
        $Hashtoken | ConvertTo-SecureString -key $AESKey | 
                ForEach-Object {[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))}
    }

    end{}
} #End Function
                
Function New-AESHASH                         {

    <#
    .Synopsis
         New-AESHASH  
    .DESCRIPTION
         New-AESHASH  will convert the AES Hash to a personal hash. The AES Hash is create and used for encrypting the Unsealkey.xml (See start-vaultinit and New-AESKey)
    .EXAMPLE
        $VaultPath =  "$env:PROGRAMFILES\Hashicorp\Vault" 
        New-AESHASH -VaultPath $VaultPath -AESKeyFile "$VaultPath\config\AESkey.txt" -AESKeyFileHash $AESKeyFileHash "$VaultPath\config\AESTokenHash.txt" 
    #>

    [CmdletBinding()]

    param(
   
        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$VaultPath      = "$env:PROGRAMFILES\Hashicorp\Vault"     ,  

        # Param help description
        [Parameter(Mandatory=$false)]    
        [string]$AESKeyFile     = "$VaultPath\config\AESkey.txt" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$AESKeyFileHash = "$VaultPath\config\AESTokenHash.txt"  
            
    )

    begin{
        # Load the Unsealkeys.xml and Decrypt with the AES KEY
        $AESKey      = get-content $AESKeyFile 
    }

    Process{
        #Create Hash from generated AES Key And safe in Vaultpath
        $hash =  $($AESKey -join " ") | ConvertTo-SecureString -asPlainText -Force  | ConvertFrom-SecureString  
        If(test-path  $AESKeyFileHash){remove-item $AESKeyFileHash -force}
        $hash | out-file $AESKeyFileHash
        If(!(test-path  $AESKeyFileHash)){
            write-warning "AESTokenHash is not created" ;
            Break
        }else{      
            write-host "The file $AESKeyFileHash with the Hashed AES token is created"
        }
    }

    End{
        # Clean up variable
        If( $AESKey ) { remove-variable -name  AESKey -force }
    }
} #End Function
Function Get-AESHash                         {
    <#
    .Synopsis
        Get-AESHASH  
    .DESCRIPTION
        Get-AESHASH  will decrypt the AESTokne hash created with tje function New-AESHASH. The token can only decrypt bij the person how has encrypt it.
    .EXAMPLE
        $VaultPath =  "$env:PROGRAMFILES\Hashicorp\Vault" 
        New-AESHASH -VaultPath $VaultPath -AESKeyFile "$VaultPath\config\AESkey.txt" -UnsealKeyXML "$VaultPath\config\UnsealKeys.xml" - AESKeyFileHash "$VaultPath\config\AESTokenHash.txt"  -APIAddress "http://192.168.16.50:8200" 
    #>

    [CmdletBinding()]

    param(
        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$VaultPath      = "$env:PROGRAMFILES\Hashicorp\Vault"     ,  

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$UnsealKeyXML   = "$VaultPath\config\UnsealKeys.xml" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$APIAddress     = "http://192.168.16.50:8200" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$AESKeyFileHash = "$VaultPath\config\AESTokenHash.txt" ,
        [Parameter(Mandatory=$false)]
        [string]$unsealkey
    )

    begin{
        # read Hash from AESKeyFilehash
        $keys        = Import-Clixml -Path $UnsealKeyXML
      
    }

    process{
        # convert AESKey from hash
        if(test-path $AESKeyFilehash){
                $AESKeyHash          = get-content $AESKeyFilehash 
                $SecureStringToBSTR  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($($AESKeyHash | ConvertTo-SecureString))
                $AESKey              = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringToBSTR)) -split (" ")   
        }else{
            $AESKey   = get-content "$VaultPath\config\aeskey.txt"
        } 


        if($unsealkey){   
            $unsealkey = Convertfrom-SecureHashAES -Hash $($keys.$unsealkey) -AESKey $AESKey
        }else{
            # Set variables for Windows
            $env:VAULT_ADDR  = $APIAddress 
            $env:VAULT_TOKEN = Convertfrom-SecureHashAES -Hash $($keys.InitialRootToken) -AESKey $AESKey
        }

   
    }

    end{
        # Clean up variables
        If( $SecureStringToBSTR ) { remove-variable -name   SecureStringToBSTR -force }
        If( $AESKey ) { remove-variable -name AESKey -force }
        If( $AESKeyHash ) { remove-variable -name AESKeyHash -force }
        If( $hash ) { remove-variable -name hash -force }
        if($unsealkey){ return $unsealkey }

    }

} #End Function
Function Set-VaultPowershellProfile          {
    <#
    .Synopsis
         Set-VaultPowershellProfile
    .DESCRIPTION
         Set-VaultPowershellProfile will a powershell profile.ps1 for loading default the vault variables and module.
    .EXAMPLE
        Set-VaultPowershellProfile 
    .EXAMPLE
        Set-VaultPowershellProfile  -append 
    #>

    [CmdletBinding()]

    param(
        # Param help description
        [Parameter(Mandatory=$false)]    
        [string]$ProfileFile =  "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [switch]$Append ,

        # Param help description
        [Parameter(Mandatory=$true)]
        [string]$VaultPath    = "$env:PROGRAMFILES\Hashicorp\Vault" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$UnsealKeyXML = "$VaultPath\config\UnsealKeys.xml" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$AESKeyFile   = "$VaultPath\config\AESTokenHash.txt"  ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$modulepath   = "C:\Program Files\WindowsPowerShell\Modules\PSVault\1.0.1\PSVault.psm1" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$APIAddress   = "http://127.0.0.1:8200" 
    )

    Begin{
        #rename Current 
        if(!($append)){
            if(test-path $ProfileFile -ErrorAction stop){
                Rename-Item -Path $ProfileFile -NewName "$(get-date -Format yyyyMMdd-HHssmm)profile.ps1.txt"
            }
        }
    }

    Process {
        # Create profile Path
          $profilePath     = @" 
#######################################################################################
#  Connect to Vault 
#######################################################################################
   
# Default variables
 [string]`$VaultPath    = "$VaultPath"
 [string]`$UnsealKeyXML = "$UnsealKeyXML"
 [string]`$AESKeyFile   = "$AESKeyFile"
 [string]`$modulepath   = "$modulepath"
 [string]`$APIAddress   = "$APIAddress"
   
# Load Hashicorp Vault Powershell module
  import-module `$modulepath -Verbose -Force 
   
# Load the Unsealkeys.xml and Decrypt with the AES KEY
  `$keys        = Import-Clixml -Path `$UnsealKeyXML
  `$AESKeyHash  = get-content `$AESKeyFile 
   
# convert AESKey from hash
  `$SecureStringToBSTR  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$(`$AESKeyHash | ConvertTo-SecureString))
  `$AESKey              = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(`$SecureStringToBSTR)   ) -split (" ") 
   
# Set variables for Windows
 `$env:VAULT_ADDR  = `$APIAddress
 `$env:VAULT_TOKEN = Convertfrom-SecureHashAES -Hash `$(`$keys.InitialRootToken) -AESKey `$AESKey
 `$headers = @{
   "X-Vault-Token" = `$env:VAULT_TOKEN
 }
   
# Load Default values for API requests to Hashicorp vault
  `$Prefix      = "/v1" 
  `$vaultObject = [pscustomobject]@{"uri" = "$APIAddress" + `$prefix 
                            "auth_header" = @{"X-Vault-Token" = `$env:VAULT_TOKEN}
                 }
#######################################################################################


"@
          $profilePath | out-file $ProfileFile       
    }

    End{   
      if(test-path $ProfileFile){
        write-host "[vault]   : Added Vault access to powershellprofile ($ProfileFile) " -for Green
        return $true
      }else{
        write-host "[vault]   : Error createing powershellprofile ($ProfileFile)" -for red
        return $false
      }#EndIf
    }

} #End Function
Function Remove-StringSpecialCharacter       {
<#
.SYNOPSIS
  This function will remove the special character from a string.
  
.DESCRIPTION
  This function will remove the special character from a string.
  I'm using Unicode Regular Expressions with the following categories
  \p{L} : any kind of letter from any language.
  \p{Nd} : a digit zero through nine in any script except ideographic 
  
  http://www.regular-expressions.info/unicode.html
  http://unicode.org/reports/tr18/

.PARAMETER String
  Specifies the String on which the special character will be removed

.SpecialCharacterToKeep
  Specifies the special character to keep in the output

.EXAMPLE
  PS C:\> Remove-StringSpecialCharacter -String "^&*@wow*(&(*&@"
  wow
.EXAMPLE
  PS C:\> Remove-StringSpecialCharacter -String "wow#@!`~)(\|?/}{-_=+*"
  
  wow
.EXAMPLE
  PS C:\> Remove-StringSpecialCharacter -String "wow#@!`~)(\|?/}{-_=+*" -SpecialCharacterToKeep "*","_","-"
  wow-_*

.NOTES
  Francois-Xavier Cat
  @lazywinadmin
  www.lazywinadmin.com
  github.com/lazywinadmin
#>
  [CmdletBinding()]
  param
  (
    [Parameter(ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [Alias('Text')]
    [System.String[]]$String,
    
    [Alias("Keep")]
    #[ValidateNotNullOrEmpty()]
    [String[]]$SpecialCharacterToKeep
  )
  PROCESS
  {
    IF ($PSBoundParameters["SpecialCharacterToKeep"])
    {
      $Regex = "[^\p{L}\p{Nd}"
      Foreach ($Character in $SpecialCharacterToKeep)
      {
        IF ($Character -eq "-"){
          $Regex +="-"
        } else {
          $Regex += [Regex]::Escape($Character)
        }
        #$Regex += "/$character"
      }
      
      $Regex += "]+"
    } #IF($PSBoundParameters["SpecialCharacterToKeep"])
    ELSE { $Regex = "[^\p{L}\p{Nd}]+" }
    
    FOREACH ($Str in $string)
    {
      Write-Verbose -Message "Original String: $Str"
      $Str -replace $regex, ""
    }
  } #PROCESS
} #End Function

##############################################################################
# Vault Functions using api 
##############################################################################
function set-DemoInstallVault          {   

    param(
        [string]$Rootpath           = "c:" , 

        [string]$VaultPath          = "$Rootpath\vault" , 
        [string]$APIaddress         = "http://127.0.0.1:8200"  ,  
        [string]$AESKeyFileHash     = "$VaultPath\config\AESTokenHash.txt"  , 
        [string]$StoragePath        = "$VaultPath\data" , 
        [string]$Vaultversion       = "1.2.2"  , 
        
        [boolean]$EnableLDAP        = $true , 
        [string]$ldapdomain         = "lab.it",

        [boolean]$NoInternet        = $true , 
    
        #Download from hashicorp Vault for installing vault on a server without internet connection
        [boolean]$downloadManual    = $false ,
        [string]$setupfolder        = "$VaultPath\download"
    )

    begin{
        if($downloadManual){
            #run below on a host with internet connection
            $DownloadUrl  = "https://releases.hashicorp.com/vault/" + $vaultVersion + "/vault_" + $vaultVersion + "_windows_amd64.zip"            
            if(!(test-path $setupfolder)){mkdir $setupfolder}    
            $VaultZip     = "$setupfolder\vault_$($vaultversion)_windows_amd64.zip"
            Get-FileFromInternet -url $DownloadUrl -outputfile $VaultZip 
            break
        }
    }
   
    process{
        ############################################################################################################################################
        # install Vault   
        ############################################################################################################################################
        if($NoInternet){
        
            $VaultZip     = "$setupfolder\vault_$($vaultversion)_windows_amd64.zip"
        
            if(test-path $VaultZip){
                write-host "[vault]`r : $VaultZip" 
                Install-Vault -VaultPath $vaultpath -Vaultversion $Vaultversion  -vaultZip  $VaultZip | out-null
            }else{
                write-host "[vault]`r : $VaultZip not found" -for Red 
                break
            }
        }else{
            $install = Install-Vault -VaultPath $vaultpath -Vaultversion $Vaultversion | out-null
        }

        # Start-vault (will create a scheduledtask for running vault in the background)
        $State = start-vault -vaultpath $vaultpath -APIaddress $apiAddress -ReturnState 

        #Initialize Vault
        if($state.Initialized -like $false){
            start-VaultInit -apiaddress $APIaddress  -VaultPath $vaultpath -Secure $true -ExportXML
        }

        #--------------------------------------------------------
        # Secure AES key with personal HASH (Powershell)
        #--------------------------------------------------------
        # Enrcypt aeskey with current windows credentials.
            if( (test-path "$VaultPath\config\AESkey.txt")) {
                New-AESHASH -VaultPath $VaultPath -AESKeyFile "$VaultPath\config\AESkey.txt" -AESKeyFileHash $AESKeyFileHash 
                if( (test-path "$VaultPath\config\AESkey.txt") -and (test-path $AESKeyFileHash) ){ 
                    remove-item "$VaultPath\config\AESkey.txt" 
                }#EndIf
            }#EndIf

        # Read encrypted keys
            Get-AESHash -VaultPath $VaultPath  -UnsealKeyXML  "$VaultPath\config\UnsealKeys.xml" -APIAddress $APIaddress -AESKeyFileHash $AESKeyFileHash -Verbose

        # Create Powershell profile.ps1 with variabels to login into vault.
            if( !(test-path "$env:USERPROFILE\Documents\WindowsPowerShell")){ mkdir "$env:USERPROFILE\Documents\WindowsPowerShell"}
            set-VaultPowershellProfile -VaultPath $VaultPath `
                                       -ProfileFile "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1" `
                                       -APIAddress $APIaddress
        # Reload Profile
          . "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1" 

        # Unseal Vault
              start-VaultautoUnseal -apiaddress $apiaddress -VaultPath $vaultpath -UnsealKeyXML $UnsealKeyXML -AESKeyFileHash $AESKeyFileHash

        # setup LDAP
            if($EnableLDAP){
                set-VaultLDAP -upndomain $LdapDomain
            }

    }

    end{
    
    }


    
} #EndFunction
Function Install-Vault                 {
    <#
     .Synopsis
         install-Vault
     .DESCRIPTION
        install-Vault
     
        Default parameters are
        VaultPath    = C:\Program Files\Hashicorp
        ConfigHcl    = C:\Program Files\Hashicorp\vault\config.hcl
        Vaultversion = 1.1.0
        ipadress     = "Your IPaddres"
        StoragePath  = C:/Program Files/Hashicorp/vault/data
        apiaddr      = http://$ipadress:8200
        FilePath     = C:\Program Files\Hashicorp\vault\config.hcl
        encoding     = ascii
        vaultZip     = 
     .EXAMPLE     
        install-Vault -VaultPath $env:ProgramFiles\Hashicorp\Vault -Vaultversion "1.1.0"
     .EXAMPLE
        install-Vault -VaultPath $env:ProgramFiles\Hashicorp\Vault -Vaultversion "1.1.0" -vaultzip c:\temp\vault_1.1.0_windows_amd64.zip
    #>    
  
    [CmdletBinding()] 
     
    param(
        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$VaultPath    = "$env:ProgramFiles\Hashicorp\vault" ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$ConfigHcl    = "$VaultPath\config.hcl",

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$Vaultversion = "1.1.1" ,

        # Param help description
        [Parameter(Mandatory=$false)]               
        #[string]$ipadress     = (Get-NetIPAddress | where-object {$_.InterfaceAlias  -eq "Ethernet0"}).IPAddress[1] 
        [string]$ipadress     = "127.0.0.1"  ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$StoragePath  = ("$vaultPath\data"),
        
        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$apiaddr      = "http://" + $ipadress + ":8200",

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$FilePath     = $ConfigHcl ,

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$encoding     = "ascii",

        # Param help description
        [Parameter(Mandatory=$false)]
        [string]$vaultZip,


        # Param help description
        [Parameter(Mandatory=$false)]
        [switch]$forceinstall,

        $ForceDownload = $true
       
    )

    begin{
   
        Function New-VaultFolder {
            <#
            .Synopsis
                New-VaultFolder
            .DESCRIPTION
                New-VaultFolder           
            .EXAMPLE     
                New-VaultFolder -path c:\vault
            #>  

            [CmdletBinding()] 

            param(
                # Param help description
                [Parameter(Mandatory=$true)]
                $Path
            )

            write-host "[vault]   : create folder $Path" -for Yellow -NoNewline; 
            
            if(!(test-path $Path)){
                mkdir $Path | out-null
            
                if(test-path $Path){
                    write-host "" 
                    return $true
                }else{
                    write-host "  Failed" -for red
                    return $false
                }#endIf

            }else{
                write-host "[vault]   : $path already exists " -for 
                return $true
            }
           
        }#End Function

        #Create folders for vault
        if(!(test-path $vaultPath))              { $create = New-VaultFolder $vaultPath               ; if($Create -like $false){Break}  } 
        if(!(test-path $storagePath))            { $create = New-VaultFolder $storagePath             ; if($Create -like $false){Break}  }
        if(!(test-path $vaultPath\log))          { $create = New-VaultFolder $vaultPath\log           ; if($Create -like $false){Break}  }
        if(!(test-path $vaultPath\config))       { $create = New-VaultFolder $vaultPath\config        ; if($Create -like $false){Break}  }
        if(!(test-path $vaultPath\config\policy)){ $create = New-VaultFolder $vaultPath\config\policy ; if($Create -like $false){Break}  }

        #Add vault to environment Path
        Add-Path -NewPath $vaultPath

        #Test internet connection, If Vault is already installed and the foreceinstall parameter
        if ( (test-path  $vaultPath\vault.exe ) -and (!($forceinstall -like $true))) {
            #Write-host "[Vault]  : Vault is already installed. Use the parameter -forceinstall to reinstall vault." -for Green
        }else{
            if($vaultZip){
                Write-host "VAULTZIP" -for Yellow
            }else{
            If(!((test-connection -ComputerName www.nu.nl -Count 1 -Quiet) -or $ForceDownload -eq $true)) {
                if (!($vaultZip)) {
                    Write-Host -ForegroundColor Red -NoNewline "[Note]    : Internet Connection down..."
                }
                Write-Host ""
                Start-Sleep 3
                if (!($vaultZip)) {                    
                     $vaultZip = "notfound"                   
                }else{              
                    if(test-path $vaultzip -ErrorAction stop){
                        Write-Host -ForegroundColor green "[Note]    : Zipfile founded"
                    }else{                   
                        $vaultZip = "notfound"
                    }#endif
                }#endif
                
                If (!($vaultZip) -or ($vaultZip -like "notfound")) {
                    If ($vaultZip -like "notfound"){              
                        write-Host -ForegroundColor Red "[Note]    : zipfile $vaultZip. Please Enter Filepath to downloaded zip file."
                    }else {
                        write-Host -ForegroundColor Red "[Note]    : zipfile $vaultZip not Found. Please Enter Filepath to downloaded zip file."
                    }#endIf
                    
                    $NameOfZip = "vault_" + $vaultVersion + "_windows_amd64.zip"

                    $vaultZip  = Read-Host -Prompt  " Enter path to zipfile" 
                    $vaultzip = $vaultZip.replace('"','')
                    if(test-path $vaultZip){               
                        Write-Host -ForegroundColor green "[Note]    : Zipfile founded"                
                    }else{                
                        write-Host -ForegroundColor Red -NoNewline "[Note]    : zipfile $vaultZip not found. Script will abort."                
                        $continue = $false
                    }#EndIf
                }#endif
    
            }Else{
                Write-Host -ForegroundColor green -NoNewline "[vault]   : Internet Connection OK"
                Write-Host ""

                #Download Vault from Hashicorp  
                $DownloadUrl  = "https://releases.hashicorp.com/vault/" + $vaultVersion + "/vault_" + $vaultVersion + "_windows_amd64.zip" 
            }#EndIf
            }
        }#EndIf

    }

    process{

        #Download
        if($DownloadUrl){
            if(test-path $vaultpath\vault.exe){
                $CurrentVaultVersion = (& "$vaultPath\vault.exe" -version) -split(" ")
                $CurrentVaultVersion = new-object -TypeName psobject -Property @{
                    Appname = $CurrentVaultVersion[0]
                    version = ($CurrentVaultVersion[1]) -replace ("v","")
                    hash    = ($CurrentVaultVersion[2]) 
                }
               
                Write-host "[Vault]   : Vault ($($CurrentVaultVersion.version)) is already installed. If you want to upgrade Vault, stop vault and replace vault.exe" -for Green
            }else{                
                $download = get-DownloadAndUnzip -DownloadUrl $DownloadUrl -unzipPath "$vaultPath" 
            } 

        }elseif($vaultZip){
            if (!(Get-Command get-Unzip -errorAction SilentlyContinue)){write-warning "could not find get-Unzip. Script will abort"; break}
            if(test-path $vaultZip){
                    if(test-path $vaultpath\vault.exe){
                        Write-host "[Vault]   : Vault is already installed. If you want to upgrade Vault, stop vault and replace vault.exe"  -for Green
                    }else{
                        $unzip = get-Unzip -zipfile $vaultZip -unzipPath "$VaultPath"   
                    }        
            }else{
                Write-warning "Could not find zip file $vaultZip"
                break
            }#EndIf           
        }#EndIf
        If(test-path "$vaultPath\Vault.exe"){
            Write-verbose "vault.exe is downloaded and added to folder $vaultPath"
        }else{
            write-warning "error downloading vault"
            break
        }#EndIf   

        #Create Config.hcl
        If(!(test-path $ConfigHcl)){
            $config_hcl = @"
storage "file" {
  path = "$(($storagePath).replace("\","/"))"
}

listener "tcp" {  
    address     = "0.0.0.0:8200"
    tls_disable = 1
}

api_addr      = "$apiaddr" 
ui            = true
disable_mlock = true


"@ 

            $config_hcl | out-file -FilePath $ConfigHcl  -Encoding $encoding 

        }#EndIf

        If (!(test-path  $ConfigHcl) ){
            Write-warning "Config.Hcl ($ConfigHcl) not found" ; 
            break
        }#EndIf

    }

    end{
       
        Write-host "[vault]   : Hashicorp Vault is installed"  -for green
        
        return $apiaddr 
    }

} #EndFunction
Function Start-Vault                   {
    <#
    .Synopsis
     start-vault
    .DESCRIPTION
     start-vault
    .EXAMPLE     
     $StartVault = start-vault -vaultpath $vaultpath -APIaddress "http://127.0.0.1:8200" 
    .EXAMPLE   
                  
    #>    
  
    [CmdletBinding()] 
     
    param(
        [Parameter(Mandatory=$true)]
        $vaultpath       ,

        [Parameter(Mandatory=$true)]
        $APIaddress    ,

        [Parameter(Mandatory=$false)]
        [array]$UnsealKeys ,

        [Parameter(Mandatory=$false)]
        [int]$Keycount = 3 ,
        
        [Parameter(Mandatory=$false)]
        [boolean]$autoInit  = $false ,

        [Parameter(Mandatory=$false)]
        [boolean]$Unseal    = $false,

        [Parameter(Mandatory=$false)]
        [switch]$ReturnState ,

        [Parameter(Mandatory=$false)]
        [string]$WindowsStyle = "Minimized" , 

        [Parameter(Mandatory=$false)]
        $taskname = "Hashicorp_Vault"
       

    )

    begin{
        #$env:VAULT_ADDR  = $APIaddress
        #$env:VAULT_Token = $Token         
    }

    process{
     
        #Start Vault     
        $action  = New-ScheduledTaskAction -Execute "$vaultpath\vault.exe" -Argument "server -config=`"$vaultpath\config.hcl`"" 
        $trigger = New-ScheduledTaskTrigger -AtStartup 
         
        Try{
            $createTask = Register-ScheduledTask -Action $action `
                                                    -Trigger $trigger `
                                                    -TaskName $taskname `
                                                    -Description "Run Hashicorp Vault" `
                                                    -User system `
                                                    -ErrorAction stop
            if($createTask){
                remove-variable -name createTask
            }#EndIf
        }Catch{
            write-host "[Vault]   : The Vault task already exists" -for green
        }#EndTryCatch

        If (!((get-ScheduledTask -TaskName $taskname).state -like "running")) {
            Write-host "[Vault]   : Start vault task " -for yellow

            start-ScheduledTask -TaskName $taskname

            If((get-ScheduledTask -TaskName $taskname).state -like "running"){
                Write-host "[Vault]   : vault task is running" -for green
            }else{
                Write-host "[Vault]   : vault task is not running (state = $((get-ScheduledTask -TaskName $taskname).state))" -for red
            }#EndIf
        }else{
            Write-host "[Vault]   : vault task is running" -for green
        }$endIf

        Start-Sleep 5
       
        # check Currentstate
            $CurrentState   = get-Vaultstatus -APIAddress $APIaddress 

        # Check if vault is started

            If($CurrentState){ 
            write-host "[vault]   : started succesfull "  -for green            
  
       
            # Show address to access vault via the browser
                write-host "[vault]   : open $($APIaddress) to connect via Browser to Vault " -ForegroundColor green 

            }#EndIf
    }

    end{
        If($returnState){
            get-Vaultstatus -APIAddress $APIaddress
        }

    }


} #EndFunction
Function Remove-Vault                  {
    <#
        .Synopsis
        Remove-Vault 
        .DESCRIPTION
        Remove-Vault will remove vault
        - stop vault by stopping the task
        - remove the task Hashicorp_Vault for taskscheduler
        - remove de folder (recursive) $vaultpath
        .EXAMPLE     
        Remove-Vault -confirm $true
        .EXAMPLE     
        Remove-Vault -vaultpath 'C:\Program Files\hashicorp\vault' -confirm $true
        Remove-Vault -vaultpath "C:\applic\cloud\vault"  -confirm $true
            
    #>    
  
    [CmdletBinding()] 

    Param(
        [Parameter(Mandatory=$false)]
        $vaultpath = "$env:programfiles\hashicorp\vault"  ,

        [Parameter(Mandatory=$false)]
        $taskName = "Hashicorp_Vault" ,

        [Parameter(Mandatory=$false)]
        [boolean]$confirm=$false 

    )

    Begin{
        write-host "#################################################" -for Magenta
        write-host "  Uninstall Hashicorp Vault                      " -for Magenta
        write-host "#################################################" -for Magenta
    }

    Process{
        if($confirm -like $true){
            # Stop Vault if running           
            Try{
                Write-host "- stop vault"
                $check = Get-ScheduledTask -TaskName "Hashicorp_Vault" -ErrorAction stop
                If ( (Get-ScheduledTask -TaskName "Hashicorp_Vault").state -eq "running"){
                    stop-VaultTask -Taskname "Hashicorp_Vault"
                }Else{
                    Write-host "  TaskState = Stopped" 
                }#endTryCatch
            }catch{
                Write-host "  TaskState = not found" 
            }#endTryCatch
 
            # Remove task
            Try{
                Write-host "- remove task Hashicorp_Vault"
                $check = Get-ScheduledTask -TaskName "Hashicorp_Vault" -ErrorAction stop
                Unregister-ScheduledTask "Hashicorp_Vault" -Confirm:$false

                Try{
                    $check = Get-ScheduledTask -TaskName "Hashicorp_Vault" -ErrorAction stop
                }catch{
                    Write-host "  TaskState = not found" 
                }#endTryCatch
            }catch{
                Write-host "  TaskState = not found" 
            }#endTryCatch
    
            # Remove Vault directory from vaultpath
            Write-host "- remove $vaultpath"
            If ((Get-Location).Path -like "*Hashicorp*") { 
                cd $env:USERPROFILE
            }#EndIf
      
            If(!(test-path $vaultpath)){
                Write-host "  Directory = not found ($vaultpath)"  
            }else{
                Remove-Item -path $vaultpath  -recurse
                If(!(test-path $vaultpath)){
                    Write-host "  Directory = not found ($vaultpath)"  
                }#EndIf
            }#EndIf
           
           


        }else{
        Write-warning "[Note] : Use the parameter -confirm $true to delete vault"
        Write-host "Remove-Vault actions : "
        write-host "    - stop vault by stopping the task"
        write-host "    - remove the task Hashicorp_Vault for taskscheduler"
        write-host "    - remove de folder (recursive) $vaultpath"
        }
    
    }

    End{}

} #EndFunction

#Vault Status
function get-vaultstatus               {
    <#
    .Synopsis
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        get-vaultstatus -VaultObject $(Get-Vault -Address $env:VAULT_ADDR -Token $env:VAULT_TOKEN)
    .EXAMPLE
        get-vaultstatus -apiaddress "http://127.0.0.1:8200"
    #>
 
    [CmdletBinding()]

    param(
        # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 1')]
        $VaultObject  ,
            # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 2')]
        $apiaddress 
    )

    begin{   
    }

    process{

            Try{

            if($VaultObject.uri -like "http*://*.*.*.*:*/v1/"){
                $Vaultstate = Invoke-RestMethod -uri $($VaultObject.uri + "sys/seal-status") -Method get   
            }else{
                $Vaultstate = Invoke-RestMethod -uri $($apiaddress + "/v1/sys/seal-status") -Method get 
            }#EndIf

            }catch{

            $Get_Error         = $error[0]
            $statusException   = $Get_Error.Exception.Message
            $StatusCode        = $Get_Error.Exception.Response.StatusCode.value__
            $StatusCodeMessage =  Get-VaultStatuscode -StatusCodes $StatusCode

            Write-warning "[vault] : $StatusCode | $statusException "
            Write-warning "[vault] : $StatusCodeMessage "    
        }
 
 
    }

    end{
        return $Vaultstate
    }

    } #EndFunction 
function get-VaultStatuscode           {
    <#
    .Synopsis
     get-VaultStatuscode
    .DESCRIPTION
     get-VaultStatuscode will convert status code to message
    .EXAMPLE  
     get-VaultStatuscode -StatusCodes 400           
    #>    
  
    [CmdletBinding()] 

    param(
        [ValidateSet("200", "204", "400", "403", "404", "429", "473", "500", "502", "503")]
        $StatusCodes
    
    )

    switch ($StatusCodes){
        '200' {$message = "200 | Success with data."}
        '204' {$message = "204 | Success, no data returned."}
        '400' {$message = "400 | Invalid request, missing or invalid data."}
        '403' {$message = "403 | Forbidden, your authentication details are either incorrect, you don't have access to this feature, or - if CORS is enabled - you made a cross-origin request from an origin that is not allowed to make such requests."}
        '404' {$message = "404 | Invalid path. This can both mean that the path truly doesn't exist or that you don't have permission to view a specific path. We use 404 in some cases to avoid state leakage."}
        '405' {$message = "405 | "}
        '429' {$message = "429 | Default return code for health status of standby nodes. This will likely change in the future."}
        '473' {$message = "473 | Default return code for health status of performance standby nodes."}
        '500' {$message = "500 | Internal server error. An internal error has occurred, try again later. If the error persists, report a bug."}
        '502' {$message = "502 | A request to Vault required Vault making a request to a third party; the third party responded with an error of some kind."}
        '503' {$message = "503 | Vault is down for maintenance or is currently sealed. Try again later. "}
        Default {}
    }

    return $message 

} #EndFunction
function get-Vaultobject               {
    <#
    .Synopsis
        Return an Object containing Vault connection details.
    .DESCRIPTION
        This is session variable required by all other Cmdlets.
    .EXAMPLE
        PS C:\> $vaultobject = get-Vault -Address 127.0.0.1 -Token 46e231ee-49bb-189d-c58d-f276743ececa
    .EXAMPLE
        PS C:\> $vaultobject = Get-Vault -Address $env:VAULT_ADDR -Token $env:VAULT_TOKEN
    #>

    [CmdletBinding()]


    Param (
        # Server Address
        [Parameter(Mandatory=$true,Position=0)]
        [String]
        $Address ,

        # Client token
        [Parameter(Mandatory=$true,Position=1)]
        [String]
        $Token 

        # prefix for vault path
        #[Parameter(Mandatory=$false)]
        #[String]$prefix      = "/v1/" 
    )

    begin{
        if($Address -notlike "http://*.*.*.*:8200"){$Address = "http://127.0.0.1:8200" }
    }

    process{
    
        $vaultobject = [PSCustomObject]@{'uri'= $Address + $prefix
                            'auth_header' = @{'X-Vault-Token'=$Token}
                            } 
    }

    end{
        return  $vaultobject
    }
} #EndFunction

#Vault Initialize
Function start-VaultInit               {
    <#
        .Synopsis
            start-VaultInit 
        .DESCRIPTION
        start-VaultInit  
        .EXAMPLE 
        start-VaultInit -APIAddress http://127.0.0.1:8200 -VaultPath c:\vault
        .EXAMPLE     
        start-VaultInit -APIAddress 
        #>    
      
    [CmdletBinding()] 
    
    param(
        # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 1')]
        $VaultObject  ,
            # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 2')]
        $apiaddress ,
    
        #Param help
        [Parameter(Mandatory=$false)]     
        $secret_shares    = 5 ,
            
        #Param help
        [Parameter(Mandatory=$false)]     
        $secret_threshold = 3 ,
            
        #Param help
        [Parameter(Mandatory=$false)]       
        [switch]$ExportXML ,
    
        #Param help
        [Parameter(Mandatory=$true)]   
        [string]$VaultPath  ,
            
        #Param help
        [Parameter(Mandatory=$false)]   
        [string]$Exportfile = "$VaultPath\config\UnsealKeys.xml" ,
            
        #Param help
        [Parameter(Mandatory=$false)]
        [boolean]$Secure    = $true ,
            
        #Param help
        [Parameter(Mandatory=$false)]
        [string]$AESKeyFile = "$VaultPath\config\AESkey.txt"   
    
    )
    
    begin{
           
    
        #Check Status
        if($VaultObject){
            $Vaultinit = get-vaultstatus -VaultObject $VaultObject
        }elseif($apiaddress){
            $Vaultinit = get-vaultstatus -apiaddress $apiaddress 
        }else{
            $Vaultinit = get-vaultstatus -apiaddress "http://127.0.0.0:8200"  
        }

        If (($Vaultinit).Initialized -eq $true) {
            $continue = $false    
            write-host  $false       
        }else{
            $continue = $true
            write-host  $true   
        } #End   
    }
    
    process{
        If (($Vaultinit).Initialized -eq $FALSE -and $continue -like $true) {
            write-host "Initialized Vault"
             
            if($secret_shares -gt 1 -and $secret_threshold -lt 2){
                Write-warning "invalid seal configuration: threshold must be greater than one for multiple shares"
                break
            }else{
                #Check Status
                if($VaultObject){
                    $uri  = $VaultObject.uri + "/v1/sys/init"
                }elseif($apiaddress){
                    $uri  = $apiaddress + "/v1/sys/init" 
                }else{
                    $uri  =  "http://127.0.0.1:8200/v1/sys/init"   
                }
                  
                $data = "{`"secret_shares`": $secret_shares, `"secret_threshold`": $secret_threshold}"
        
                  
                $initialize = Invoke-RestMethod -uri $uri  `
                                                -Method post `
                                                -body $data 
            }#EndIf
    
            $VaultINITKeys = new-object -TypeName psobject -Property @{
                UnsealKey1         = $($initialize.keys)[0]
                UnsealKey2         = $($initialize.keys)[1]
                UnsealKey3         = $($initialize.keys)[2]
                UnsealKey4         = $($initialize.keys)[3]
                UnsealKey5         = $($initialize.keys)[4]
                UnsealKey_base64_1 = $($initialize.keys_base64)[0]
                UnsealKey_base64_2 = $($initialize.keys_base64)[1]
                UnsealKey_base64_3 = $($initialize.keys_base64)[2]
                UnsealKey_base64_4 = $($initialize.keys_base64)[3]
                UnsealKey_base64_5 = $($initialize.keys_base64)[4]
                InitialRootToken   = $($initialize.root_token)
            } | select-object UnsealKey1,UnsealKey2,UnsealKey3,UnsealKey4,UnsealKey5,InitialRootToken,UnsealKey_base64_1,UnsealKey_base64_2,UnsealKey_base64_3,UnsealKey_base64_4,UnsealKey_base64_5  
        } #EndIf  
    }
    
    end{
    
        If ($continue -eq $false) {
            write-host "[Vault]   : vault is already initialized!!" -for green
        }else{
            if($VaultINIT){ remove-variable -name VaultINIT -force }
    
            If($ExportXML){
                if($secure -eq $true){
                    #Export the Convertto-SecureHashAES  -token $token -tokenName UnsealKey1 -AESKey $AESKey 
                    $AESKey        = new-AESKey 
                    $EncryptedKeys = new-object -TypeName psobject -Property @{     
                           
                        UnsealKey1         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey1)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
                        UnsealKey2         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey2)" -tokenName "UnsealKey2" -AESKey $AESKey).hash 
                        UnsealKey3         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey3)" -tokenName "UnsealKey3" -AESKey $AESKey).hash 
                        UnsealKey4         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey4)" -tokenName "UnsealKey4" -AESKey $AESKey).hash 
                        UnsealKey5         = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey5)" -tokenName "UnsealKey5" -AESKey $AESKey).hash 
                        UnsealKey_base64_1 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_1)" -tokenName "UnsealKey1" -AESKey $AESKey).hash 
                        UnsealKey_base64_2 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_2)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
                        UnsealKey_base64_3 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_3)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
                        UnsealKey_base64_4 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_4)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
                        UnsealKey_base64_5 = (Convertto-SecureHashAES -token "$($VaultINITKeys.UnsealKey_base64_5)" -tokenName "UnsealKey1" -AESKey $AESKey).hash
                        InitialRootToken   = (Convertto-SecureHashAES -token "$($VaultINITKeys.InitialRootToken)" -tokenName "InitialRootToken" -AESKey $AESKey).hash 
                        } | select-object UnsealKey1,UnsealKey2,UnsealKey3,UnsealKey4,UnsealKey5,InitialRootToken,UnsealKey_base64_1,UnsealKey_base64_2,UnsealKey_base64_3,UnsealKey_base64_4,UnsealKey_base64_5
                         
                        Try{
                        write-host "`$EncryptedKeys | Export-Clixml -Path $exportfile"
                        $EncryptedKeys | Export-Clixml -Path $exportfile
                        }catch {
                        $exportfile = read-host -Prompt "Exportfile"
                        }
                    
                        $AESKey | out-file -FilePath $AESKeyFile                 
    
                }else{
                    $VaultINITKeys | Export-Clixml -Path $exportfile
                }
               
            }
    
            write-host "===============================================================" -ForegroundColor Magenta
            write-host " HASHICORP VAULT  - Unseal Keys and Roottokens "                 -ForegroundColor Magenta
            write-host "===============================================================" -ForegroundColor Magenta
            write-warning "Keys are generated ONCE!!"
            write-warning " --> If you close the screen the keys are gone!!!! "
            write-host "==============================================================="
            write-host " UnsealKey1        : $($VaultINITKeys.UnsealKey1)"
            write-host " UnsealKey2        : $($VaultINITKeys.UnsealKey2)"
            write-host " UnsealKey3        : $($VaultINITKeys.UnsealKey3)"
            write-host " UnsealKey4        : $($VaultINITKeys.UnsealKey4)"
            write-host " UnsealKey5        : $($VaultINITKeys.UnsealKey5)"
            write-host " UnsealKey1 base64 : $($VaultINITKeys.UnsealKey_base64_1)"
            write-host " UnsealKey2 base64 : $($VaultINITKeys.UnsealKey_base64_2)"
            write-host " UnsealKey3 base64 : $($VaultINITKeys.UnsealKey_base64_3)"
            write-host " UnsealKey4 base64 : $($VaultINITKeys.UnsealKey_base64_4)"
            write-host " UnsealKey5 base64 : $($VaultINITKeys.UnsealKey_base64_5)"
            write-host " InitialRootToken  : $($VaultINITKeys.InitialRootToken)"
            write-host ""
            write-host "Vault initialized with 5 key shares and a key threshold of 3. "
            write-host "Please securely distribute the key shares printed above. When the Vault is re-sealed,"
            write-host "restarted, or stopped, you must supply at least 3 of these keys to unseal it"
            write-host "before it can start servicing requests."
            write-host ""
            write-host "Vault does not store the generated master key. Without at least 3 key to"
            write-host "reconstruct the master key, Vault will remain permanently sealed!"
            write-host ""
            write-host "It is possible to generate new unseal keys, provided you have a quorum of"
            write-host "existing unseal keys shares. See `"vault operator rekey`" for more information."
            write-host "===============================================================" -ForegroundColor Magenta
                
            if($VaultINITKeys){ remove-variable -name VaultINITKeys -force }
        }#eNDIF    
    }#End
    
} #EndFunction

#Vault (Un)Seal
function set-VaultUnseal               {
    <#
    .Synopsis
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        set-VaultUnseal 
    .EXAMPLE
        set-VaultUnseal 
    #>
 
    [CmdletBinding()]

    param(
        # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 1')]
        $VaultObject  ,
            # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 2')]
        $apiaddress ,
            
        # Param1 help description
        [Parameter(Mandatory=$true)]
        $unsealkey        
    )
    
    $Payload = '{
        "key": "' + $unsealkey + '"
    }'
    if($VaultObject){
        $uri = $VaultObject.uri + "/v1/sys/unseal"
        $unseal = Invoke-RestMethod -uri $uri -headers $($vaultObject.auth_header) -Method put -body $Payload 
    }elseif($apiaddress){
        $uri = $apiaddress  + "/v1/sys/unseal"
        $unseal = Invoke-RestMethod -uri $uri -Method put -body $Payload 
    }else{
        $uri = "http://127.0.0.0:8200/v1/sys/unseal"
        $unseal = Invoke-RestMethod -uri $uri -Method put -body $Payload 
    }
        
        
    if($unseal.sealed -like $true) {
        write-warning "[vault] : Vault is sealed (progress ($($unseal.progress)/$($unseal.t))"
    }
    if($unseal.sealed -like $false){
        write-verbose "[vault] : Vault is unsealed" 
    }
    
} #EndFunction
function set-VaultSeal                 {

    <#
    .Synopsis
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        set-VaultSeal -vaultobject $vaultobject
    .EXAMPLE
        set-VaultSeal -apiadress http://127.0.0.1:8200
    #>
 
    [CmdletBinding()]
    param(
        # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 1')]
        $VaultObject  ,
            # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 2')]
        $apiaddress      
)

begin{
    write-warning "Vault wil be sealed!! "
    write-warning "Vault wil not be accesible anymore."
    $userInput = Read-Host -Prompt "Type yes to continue"
}

process{
    If($userInput -like "yes"){
        #Seal Vault :
                    if($VaultObject){ 
        $uri = $VaultObject.uri + "/v1/sys/seal"
        Invoke-RestMethod -uri $uri -headers $($vaultObject.auth_header) -Method put
    }
                    if($apiaddress){
        $uri = $apiaddress + "/v1/sys/seal"
        Invoke-RestMethod -uri $uri -Method put        
    }
    }else{
        write-warning "Unseal Aborted"
    }#EndIf
}

end{
    get-vaultstatus -apiaddress "http://127.0.0.1:8200"
}
} #EndFunction
function start-VaultautoUnseal         {
      
    <#
    .Synopsis
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        auto-VaultUnseal -VaultPath c:\vault -APIAddress http://127.0.0.1:8200 
    .EXAMPLE
        set-VaultUnseal 
    #>
 
    [CmdletBinding()]

    param(
        # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 1')]
        $VaultObject  ,
        # Param1 help description
        [Parameter(Mandatory=$true, 
                Position=0,
                ParameterSetName='Parameter Set 2')]
        [string]$apiaddress ,

        # Param2 help description
        [Parameter(Mandatory=$true)]
        [string]$VaultPath  , 

        # Param3 help description
        [Parameter(Mandatory=$false)]
        [string]$UnsealKeyXML   = "$VaultPath\config\UnsealKeys.xml" , 

        # Param4 help description
        [Parameter(Mandatory=$false)]
        [string]$AESKeyFileHash = "$VaultPath\config\AESTokenHash.txt" 
          
    )
    $keys = Import-Clixml -Path $UnsealKeyXML
    #Check Unseal
    $i=1
    do{
        $sealstatus = (get-vaultstatus -apiaddress $APIAddress).sealed -eq $true
        sleep 1
        If($sealstatus -eq $true){  
            if( test-path $AESKeyFileHash ){
                $unsealkey =  Get-AESHash -VaultPath $VaultPath -APIAddress $APIAddress -AESKeyFileHash $AESKeyFileHash -UnsealKeyXML $UnsealKeyXML -unsealkey "UnsealKey$($i)"
            }else{                    
                $AESKey = get-content "$VaultPath\config\AESkey.txt"
                $unsealkey = Convertfrom-SecureHashAES -Hash $($keys."UnsealKey$($i)") -AESKey $AESKey 
            }
            if($VaultObject){
                set-VaultUnseal -VaultObject $VaultObject -unsealkey $unsealkey 
                $sealstatus =  (get-vaultstatus -VaultObject $VaultObject).sealed
            }else{
                set-VaultUnseal -apiaddress $apiaddress -unsealkey $unsealkey 
                $sealstatus =  (get-vaultstatus -apiaddress $APIAddress).sealed
            }   
            If($sealstatus -eq $false){
                write-host "[vault] : Vault is unsealed"   -for Green
            }          
        }Else{
            write-host "[vault] : Vault is unsealed"   -for Green
        }
            $i++
    }while ($sealstatus -eq $true)
} #EndFunction

#Vault default config example
function set-vaultconfig               {
    <#
    .Synopsis
     set-vaultconfig 
    .DESCRIPTION
     set-vaultconfig will configure vault with grops and policies as examples. Just for test
    .EXAMPLE  
     set-vaultconfig - password 'H@shiCorp12!'       
    #>    
  
    [CmdletBinding()] 

    param(
        $password = 'H@shiCorp12!' 
       
    )

    #######################################
    # Configure Vault
    #######################################
    # Get Version
        $version = vault version ; $version
        write-host "Vault version = $version "
    # Set VAULT_token with Initial Roottoken for first login and config
        $token = Convertfrom-SecureHashAES -Hash $($keys.InitialRootToken) -AESKey $AESKey
        write-host "Token         = $token "
          
    # Login with Root token
        $ConnectToVault = connect-Vault -token $token -VaultPath $VaultPath -APIAddress $APIAddress -quite
        $ConnectToVault 

    # Create policy
        Write-host "[vault]   : Set Policy" -for Magenta
        New-VaultPolicy -VaultPath $VaultPath -PolicyPath "$VaultPath\config\policy" -PolicyName p_Vault_Admin  -capabilities "[`"read`",`"list`",`"create`",`"update`",`"delete`"]" -path "*" 
        New-VaultPolicy -VaultPath $VaultPath -PolicyPath "$VaultPath\config\policy" -PolicyName p_Vault_Reader -capabilities "[`"read`",`"list`"]" -path "*"
        New-VaultPolicy -VaultPath $VaultPath -PolicyPath "$VaultPath\config\policy" -PolicyName p_Vault_Reader -capabilities "[`"read`",`"list`"]" -path "cubbyhole/*"  -append

    # Internal groupsget-vault
        Write-host "[vault]   : Default Groups" -for Magenta
        vault write identity/group name="g_Vault_Admin"  policies="p_Vault_Admin"  type="internal" metadata=Team="Cloud Platform team" metadata=region="Europe"
        vault write identity/group name="g_Vault_Reader" policies="p_Vault_Reader" type="internal" metadata=Team="Cloud Platform team" metadata=region="Europe"

    # Userpass AUTH
        Write-host "[vault]   : Enabled userpass Auth" -for Magenta
        $AuthMethods = vault auth list  #-format=json | convertfrom-json
        $AuthMethods
    # Enable Userpass 
        $ErrorActionPreference = "stop"
                    Try{           
        $EnableUserpass = vault auth enable userpass
        write-host "[userpass] :  $EnableUserpass" -for Green
            }Catch{
        write-host "[userpass] : Userpass already enabled"    -for Green
    }#EndTryCatch
        $ErrorActionPreference = "Continue"

    # Create Vault Admin User
        
        $createuser = vault write auth/userpass/users/vaultadmin password=$password  policies="p_vault_admin"
        write-host "[userpass] :  $createuser" -for Green
        try{vault login -method=userpass username=vaultadmin  password=$password }catch{}
        $connect = connect-Vault -token $token -VaultPath $VaultPath -APIAddress $APIAddress
 
    # Create Vault Reader User
        
        $createuser = vault write auth/userpass/users/vaultreader password=$password policies="p_vault_reader"
        write-host "[userpass] :  $createuser" -for Green
        try{vault login -method=userpass username=vaultreader  password=$password}catch{}
        $connect = connect-Vault -token $token -VaultPath $VaultPath -APIAddress $APIAddress
        #vault read auth/userpass/users/vaultreader
        #vault list auth/userpass/users/
    # reconnect  
        $connect = connect-Vault -token $token -VaultPath $VaultPath -APIAddress $APIAddress

} #EndFunction

#Vault LDAP
function set-VaultLDAP                 {
    
    <#
    .Synopsis
     set-VaultLDAP
    .DESCRIPTION
     set-VaultLDAP will configure vault for ldap. After running this function you will be able to logon into vault with your ActiveDirectory credentials
    .EXAMPLE  
     set-VaultLDAP -upndomain "lab.it"      
    #>    
  
    [CmdletBinding()] 


    param(
        [string]$upndomain     = "lab.it" ,
        [string]$LDAPUrl       = "ldap://$($($upndomain.split("."))[0]).$($($upndomain.split("."))[1]):389" ,
        [string]$userattr      = "sAMAccountName",
        [string]$userdn        = "dc=$($($upndomain.split("."))[0]),dc=$($($upndomain.split("."))[1])",
        [string]$groupdn       = "dc=$($($upndomain.split("."))[0]),dc=$($($upndomain.split("."))[1])",
        [string]$groupattr     = "cn", 
        [boolean]$insecure_tls = $false
    )

    begin{
        #######################################################################
        # Active Directory AUTH
        #######################################################################
        Write-host "[vault]`t: Enabled LDAP Auth" -for Magenta
    }

    process{
      # Enable LDAP
        $ErrorActionPreference = "stop"
        Try{           
            $EnableLDAP = vault auth enable ldap
            write-host "[LDAP]`t: $EnableLDAP" -for Green

           # Run Config
             $ConfigLDAP = vault write auth/ldap/config url=$LDAPUrl userattr=$userattr userdn=$userdn groupdn=$groupdn groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" groupattr=$groupattr upndomain=$upndomain insecure_tls=$insecure_tls
             write-host "[LDAP]`t: $ConfigLDAP" -for Green
        }Catch{
             write-host "[LDAP]`t: LDAP already enabled"    -for Green
        }#EndTryCatch

        $ErrorActionPreference = "Continue"
    }

    end{}
                   
} #EndFunction

#Secret Engine
function new-VaultSecretEngine         {
   <#
    .Synopsis
     new-VaultSecretEngine
    .DESCRIPTION
     new-VaultSecretEngine will create a new secrets engine in vault
    .EXAMPLE  
        $SecretEngineName = "kv-v2-test" 
        new-VaultSecretEngine  -SecretEngineName  $SecretEngineName -vaultobject $vaultobject    
    #>    
  
    [CmdletBinding()] 

    param(
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$SecretEngineName = "test4" ,

        [Parameter(Mandatory=$true)]
        [PSCustomObject]$vaultobject  , 
            
            
     
 
        [Parameter(Mandatory=$false)]
        [boolean]$force_no_cache = $true , 
    
        [Parameter(Mandatory=$false)]
        [ValidateSet("1", "2")]
        $KV_version = 2
    
    )
    
    if($($vaultobject.uri) -like "*/v1"){
        $uri =  "$($vaultobject.uri)/sys/mounts/$SecretEngineName"  
    }elseif($($vaultobject.uri) -like "*/v1/"){
        $uri =  "$($vaultobject.uri)sys/mounts/$SecretEngineName"  
    }else{
        $uri =  "$($vaultobject.uri)/v1/sys/mounts/$SecretEngineName"  
    }  
    
    $payload = "{
`"type`": `"kv`",
`"options`": {
`"version`": `"$KV_version`"
}
}"
    
    

# Get KV Engine configuration                                            
    If ((get-VaultSecretEngine -vaultobject $vaultobject -SecretEngineName $SecretEngineName ) -like $true) {
        write-host "[vault] : secretengine $SecretEngineName already exists" -for Green
    }else{
        try{
            write-host "[vault] : secret engine $SecretEngineName does not exists and will be created" -for yellow
            $New_Secrets_Engine = Invoke-RestMethod -uri $uri  `
                                                -headers $($vaultObject.auth_header) `
                                                -Method post `
                                                -body $payload
        }catch{
            $Get_Error    = $error[0]
            $errorMessage = Remove-StringSpecialCharacter -String $($Get_Error.ErrorDetails.message) -SpecialCharacterToKeep ": -"
            $StatusCode   = $Get_Error.Exception.Response.StatusCode.value__
            $StatusCodeMessage =  Get-VaultStatuscode -StatusCodes $StatusCode
            if($($Get_Error.ErrorDetails.message) -like "*existing mount at*"){
            Write-warning "[vault] : $StatusCode | $(($errorMessage).split(":")[1]) "
            Write-warning "[vault] : $StatusCodeMessage "
            }else{
            Throw ("Failed to create secret engine for " + $uri)
            }
        } #Endif 
        sleep 3        
        If ((get-VaultSecretEngine -vaultobject $vaultobject -SecretEngineName $SecretEngineName) -like $true) {
            write-host "[vault] : secretengine $SecretEngineName is created" -for Green
        }else{
            write-host "[vault] : secretengine $SecretEngineName is not created" -for red
        }#EndIf
    }

                                             
       
} #EndFunction 
function remove-VaultSecretEngine      {
   <#
    .Synopsis
     remove-VaultSecretEngine
    .DESCRIPTION
     remove-VaultSecretEngine will create a new secrets engine in vault
    .EXAMPLE  
        $SecretEngineName = "kv-v2-test" 
        remove-VaultSecretEngine  -SecretEngineName  $SecretEngineName -vaultobject $vaultobject -confirm $true   
    #>    
  
    [CmdletBinding()]
     
    param(
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$SecretEngineName = "kv-v2-newsecret2",

        [Parameter(Mandatory=$false)]
        [PSCustomObject]$vaultobject = $(Get-Vault -Address $APIAddress -Token $env:VAULT_TOKEN) ,
            
        [Parameter(Mandatory=$false)]
        [boolean]$confirm=$true
    
    )
 
    if($($vaultobject.uri) -like "*/v1"){
        $uri =  "$($vaultobject.uri)/sys/mounts/$SecretEngineName"  
    }elseif($($vaultobject.uri) -like "*/v1/"){
        $uri =  "$($vaultobject.uri)sys/mounts/$SecretEngineName"  
    }else{
        $uri =  "$($vaultobject.uri)/v1/sys/mounts/$SecretEngineName"  
    }  


    if((get-VaultSecretEngine  -vaultobject $vaultobject -SecretEngineName $SecretEngineName) -like $true){
        write-warning "Remove secretEngine $SecretEngineName "
    
        if($confirm){
            $userInput = Read-Host -Prompt "Type yes to remove secretEngine $SecretEngineName"
        }else{
            $userInput = "yes"
        }#EndIf
    
        If($userInput -like "yes"){
            
    
            try {
                $delete_Secrets_Engine = Invoke-RestMethod -uri $uri  `
                                    -headers $($vaultObject.auth_header) `
                                    -Method Delete
    
            }catch{
                Throw ("Failed to delete secret engine from " + $uri)
            }#EndTryCatch
        }else{
            write-warning "delete of secret engine is Aborted"
        }#EndIf
        }else{
        write-host "[vault] : secretengine $SecretEngineName does not exists" -for green
         
        }
         
         
            
} #EndFunction
function get-VaultSecretEngine         {
    <#
    .Synopsis
     get-VaultSecretEngine
    .DESCRIPTION
     get-VaultSecretEngine will get the properties of a secrets engine
    .EXAMPLE  
        $SecretEngineName = "kv-v2-test" 
        get-VaultSecretEngine  -SecretEngineName  $SecretEngineName -vaultobject $vaultobject 
    #>    
  
    [CmdletBinding()]

    param(
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$SecretEngineName = "kv-v2-newsecret2",

        [Parameter(Mandatory=$true)]
        [PSCustomObject]$vaultobject  ,
            
        [Parameter(Mandatory=$false)]
        [boolean]$confirm=$true
    
    )

    try{

        if($($vaultobject.uri) -like "*/v1"){
            $uri = $VaultObject.uri  + "/" + $SecretEngineName + "/config"
        }elseif($($vaultobject.uri) -like "*/v1/"){
            $uri = $VaultObject.uri  + $SecretEngineName + "/config"
        }else{
            $uri = $VaultObject.uri  + "/v1/" + $SecretEngineName + "/config"
        }  
      
        Invoke-RestMethod -Uri $uri -Method get -Headers $VaultObject.auth_header -ErrorAction stop
        return $true
    }catch{
        $Get_Error    = $error[0]
        $errorMessage = Remove-StringSpecialCharacter -String $($Get_Error.ErrorDetails.message) -SpecialCharacterToKeep ": -"
        $StatusCode   = $error[0].Exception.Response.StatusCode.value__
        $StatusCodeMessage =  Get-VaultStatuscode -StatusCodes $StatusCode
        if($($Get_Error.ErrorDetails.message) -like "*"){
            Write-verbose "[vault] : $StatusCode | $(($errorMessage).split(":")[1]) "
            Write-verbose "[vault] : $StatusCodeMessage "
        }else{
     
            Throw ("Failed to create secret engine for " + $uri)
        }  

        return $false      
    }
    
} #EndFunction
   
#Secret
function set-VaultSecret               {

    <#
    .Synopsis
     set-VaultSecret  
    .DESCRIPTION
     set-VaultSecret will Create orcoverwrite secret in SecretEngine  
    .EXAMPLE     
        $secretPath  = "vsphere_api/admin"
        $username    = "admin" 
        $password    = "Z33rgG3H31m12!!!!" 
        $environment = "test" 
        $tag         = "tag"
        set-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath -username $username -password $password -environment $environment -tag $tag

    #>    
  
    [CmdletBinding()]
        
    param(
        $VaultObject ,
        $secretEnginename = "kv-v2-newsecret",
        $SecretPath = "eng/api/secret",
        $KvVersion = 2 ,
        $username = "administrator" ,
        $password = "G3H31m12!" ,
        $environment = "test" , 
        $tag = "tag" ,
        $server = "empty"
    
            
    )
    
    #Set path for KV version 1 or 2
    if($kvversion -like 2){
        $path = "$secretEngineName/data/$secretPath"
    }else{
        $path = "$secretEngineName/$secretPath"
    }#endIf
    
    #Check if uri contains */v1/
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri  + "/" + $Path
    }elseif($($vaultobject.uri) -like "*/v1/"){
        $uri = $VaultObject.uri  +  $Path
    }else{        
        $uri  = $VaultObject.uri + "/v1/" + $Path
    }#endIf
    
    
    try{
        $data ="{`"data`": { `"username`": `"$username`", `"password`": `"$Password`" , `"environment`": `"$environment`" , `"Tag`": `"$tag`" , `"server`": `"$server`" }}"
        Write-Debug $data
    }catch{
        throw "Cannot convert Secret to JSON"
    }
    
    $new = Invoke-RestMethod -uri $uri  `
                             -headers $($vaultObject.auth_header) `
                             -Method post `
                             -body $data | write-output
    
} #EndFunction
function get-VaultSecret               {
    <#
    .Synopsis
     get-VaultSecret  
    .DESCRIPTION
     get-VaultSecret will get the credentials form a secrets engine
    .EXAMPLE     
     get-VaultSecret -VaultObject $vaultobject -secretEnginename $SecretEngineName -SecretPath $secretPath 
    #>    
      
    param(
        $VaultObject  = $(Get-Vault -Address $APIAddress -Token $env:VAULT_TOKEN),
        $secretEnginename = "kv-v2-newsecret",
        $SecretPath = "eng/api/secret" ,
        $kvversion  = 2
    
    )
    
    if($kvversion -like 2){
        $path = "$secretEngineName/data/$secretPath"
    }else{
        $path = "$secretEngineName/$secretPath"
    }
    
    
     #Check if uri contains */v1/
    if($($vaultobject.uri) -like "*/v1"){
        $uri = $VaultObject.uri  + "/" + $Path
    }elseif($($vaultobject.uri) -like "*/v1/"){
        $uri = $VaultObject.uri  +  $Path
    }else{        
        $uri  = $VaultObject.uri + "/v1/" + $Path
    }#endIf
      
    try{
        $result = Invoke-RestMethod -uri $uri  `
                                    -headers $($vaultObject.auth_header) `
                                    -Method get 
        New-Object -TypeName psobject -Property @{
            username       = $result.data.data.username
            password       = $result.data.data.password
            server         = $result.data.data.server 
            environment    = $result.data.data.environment
            tag            = $result.data.data.Tag
            created_time   = $result.data.metadata.created_time 
            deletion_time  = $result.data.metadata.deletion_time
            destroyed      = $result.data.metadata.destroyed
            version        = $result.data.metadata.version
            request_id     = $result.request_id 
            lease_duration = $result.lease_duration
            renewable      = $result.renewable
            wrap_info      = $result.wrap_info
            warnings       = $result.warnings
            auth           = $result.auth
        }
    
    }catch{                            
        $Get_Error    = $error[0]
        $errorMessage = Remove-StringSpecialCharacter -String $($Get_Error.ErrorDetails.message) -SpecialCharacterToKeep ": -"
        $StatusCode   = $_.Exception.Response.StatusCode.value__
        if($($StatusCode ) -like "404"){
        Write-warning "[vault] : $StatusCode | no secret found in $uri"
        }else{
        Throw ("Failed to create secret engine for " + $uri)
        }
    }
    
    
} #EndFunction

##############################################################################
# VAULT Functions ; using Vault.exe
##############################################################################
#policy
Function New-VaultPolicy               {
    <#
    .Synopsis
        New-VaultPolicy
    .DESCRIPTION
        New-VaultPolicy will create a vault policy file (HCL) and will write the policy to vault
    .EXAMPLE
        New-VaultPolicy -PolicyName Vault_Admin  -capabilities  "[`"read`",`"list`",`"create`",`"update`",`"delete`"]" -path "*" 
        New-VaultPolicy -PolicyName Vault_Reader -capabilities "[`"read`",`"list`"]" -path "*" 
        New-VaultPolicy -PolicyName Vault_Reader -capabilities "[`"read`",`"list`"]" -path "secrets/*"  -append
    .EXAMPLE
        $vaultpath  = "D:\mark\Cloud\Vault"
        $PolicyPath = "$VaultPath\config\policy"
        $PolicyName = "Vault_Admin"
        $PolicyFile = "$PolicyPath\P-$PolicyName.hcl"
        $capabilities =  "[`"read`",`"list`",`"create`",`"update`",`"delete`"]" 
        $path   = "*" 
        New-VaultPolicy -VaultPath $vaultpath  -PolicyPath  $PolicyPath -PolicyName $PolicyName -PolicyFile  $PolicyFile -capabilities $capabilities -path $path
    .INPUTS
        Inputs to this cmdlet (if any)
    .OUTPUTS
        Output from this cmdlet (if any)
    .NOTES
        General notes
    .COMPONENT
        The component this cmdlet belongs to
    .ROLE
        The role this cmdlet belongs to
    .FUNCTIONALITY
        The functionality that best describes this cmdlet
    #>

    [CmdletBinding()]

    Param(
        # Param1 help description
        [Parameter(Mandatory=$false)]
        $VaultPath        = "$env:PROGRAMFILES\Hashicorp\Vault" ,

        [Parameter(Mandatory=$false)]
        $PolicyPath       = "$VaultPath\config\policy" ,
                    
        [Parameter(Mandatory=$true)]
        $PolicyName       = "Vault-Admin" ,

              
        [Parameter(Mandatory=$true)]
        $capabilities     = "[`"read`",`"list`"]" ,

        [Parameter(Mandatory=$true)]
        $Path             = "*" ,

        [Parameter(Mandatory=$false)]
        $PolicyFile       = "$PolicyPath\$PolicyName.hcl" ,

        [Parameter(Mandatory=$false)]
        [switch]$append
    )

    Begin {
     
    }

    Process{
        #Create Policy File
        If($append){
            "path `"$Path`" {"                  | out-file -Encoding ascii -FilePath $PolicyFile -append
            "    capabilities = $capabilities " | out-file -Encoding ascii -FilePath $PolicyFile -append
            "}"                                 | out-file -Encoding ascii -FilePath $PolicyFile -append
        }else{
            "path `"$Path`" {"                  | out-file -Encoding ascii -FilePath $PolicyFile 
            "    capabilities = $capabilities " | out-file -Encoding ascii -FilePath $PolicyFile -append
            "}"                                 | out-file -Encoding ascii -FilePath $PolicyFile -append                
        }#EndIf

        Try{
            $version = vault -version
            vault policy write $PolicyName $PolicyFile 
        }Catch{
            If(!(test-path $VaultPath\vault.exe)){
                Write-warning "the commnd command Vault can not be found";
                break
            }#EndIf
                        
            set-location $VaultPath
                         
            .\vault.exe policy write $PolicyName $PolicyFile 
        }#EndTryCatch

    }

    End{
      
    }
                                               
} #EndFunction
Function Remove-vaultauto              {
    <#
    .Synopsis
    Remove-vaultauto 
    .DESCRIPTION
    Remove-vaultauto will remove vault without confirmation and will clean/rename the profile.ps1 
    .EXAMPLE     
    Remove-vaultauto 
                         
    #>   
    param(
        $vaultpath = "c:\program files\Hashicorp",
        $taskName  = "Hashicorp_Vault"
    ) 
  
    Remove-Vault -vaultpath $vaultpath -taskName $taskName -confirm $true
    [string]$ProfileFile =  "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1" 
    if(test-path $ProfileFile -ErrorAction stop){
        Rename-Item -Path $ProfileFile -NewName "$(get-date -Format yyyyMMdd-HHssmm)profile.ps1.txt"
    }
} #EndFunction
Function Update-Vault                  {
    <#
    .Synopsis
     Update-Vault 
    .DESCRIPTION
     Update-Vault will remove vault
      - stop vault by stopping the task
      - remove the task Hashicorp_Vault for taskscheduler
      - remove de folder (recursive) $vaultpath
    .EXAMPLE     
     Default install path of Vault is 'C:\Program Files\Hashicorp\Vault'. 
     Update-Vault -version "1.1.0" -APIaddress "http://192.168.16.50:8200" 
    .EXAMPLE
     If vault is not installed in the default path 'C:\Program Files\Hashicorp\Vault'  
     Update-Vault -version "1.1.0" -vaultpath 'C:\apps\Hashicorp\Vault' -APIaddress "http://192.168.16.50:8200"           
    #>    
  
    [CmdletBinding()] 

    param(
        #Param help
        [Parameter(Mandatory=$true)]
        $version   = "1.1.0" ,

        #Param help     
        [Parameter(Mandatory=$false)]
        $vaultpath = 'C:\Program Files\Hashicorp\Vault' ,

        #Param help
        [Parameter(Mandatory=$true)]
        $APIaddress = "http://192.168.16.50:8200"
    )
    
    $currentversion = ((vault -version).split(" ")[1]) -replace ("v","")

    if($currentversion -eq $version){
        Write-host " The version of vault is already $version"
    }else{
        # Stop Vault
            stop-VaultTask
        # rename cuurent vault.exe
            rename-item -Path $vaultpath\vault,exe -NewName $Currentversion + "_Vault.exe"
        # Download new version      
            $DownloadUrl  = "https://releases.hashicorp.com/vault/" + $vaultVersion + "/vault_" + $vaultVersion + "_windows_amd64.zip" 
            $DownloadUrl  = get-DownloadAndUnzip -DownloadUrl $DownloadUrl -unzipPath "$vaultPath" 
        # Start-vault
            Start-Vault -vaultpath $vaultpath -APIaddress $APIAddress

            Get-VaultStatus -VaultPath $vaultpath -APIaddress $APIAddress
    }

} #EndFunction
Function Connect-Vault                 {
    <#
    .Synopsis
    Connect-Vault 
    .DESCRIPTION
    Connect-Vault via Token          
    .EXAMPLE          
    Connect-Vault -token dvfdsgdsgs8907w78r339r37823i
    .EXAMPLE          
    Connect-Vault -VaultPath "$env:ProgramFiles\Hashicorp\vault" -token dvfdsgdsgs8907w78r339r37823i
    #>    
  
    [CmdletBinding()] 
       
    param (
        [Parameter(Mandatory=$false)]
        [string]$VaultPath    = "$env:ProgramFiles\Hashicorp\vault" ,
        [Parameter(Mandatory=$false)]
        $APIAddress , 

        [Parameter(Mandatory=$true)]  
        $token ,

        [Parameter(Mandatory=$false)] 
        [switch]$quite
    )

    Begin{
                $env:VAULT_ADDR =  $apiaddress
    }

    Process{

        # login to Vault with token
            Try{
            $Version = vault -version 
            $login   = vault login $token  2>&1
            }catch{
            If(!(test-path $VaultPath\vault.exe)){
                Write-warning "the command Vault can not be found";
                break
            }#EndIf
            
            Set-Location $VaultPath       
            $login = .\vault.exe login $token  2>&1
            }#EndTryCatch

        # Output to screen
            If($($login[0].Exception) -like "*WARNING! *"){
            Write-warning "$(($login[0]).Exception.message))"
            }#EndIf
  
        # Create output object    
            $loginObj = new-object -TypeName psobject -Property @{
            token                 = $login[-7].split(" ")[-1]
            token_accessor        = $login[-6].split(" ")[-1]
            token_duration        = $login[-5].split(" ")[-1]
            token_renewable       = $login[-4].split(" ")[-1] 
            token_policies        = $login[-3].split(" ")[-1]
            identity_policies     = $login[-2].split(" ")[-1]
            policies              = $login[-1].split(" ")[-1]
            }#EndObject

    }

    End{
            if($quite){
            }else{
                $x = $login[-13..-10]
                write-host "$($x[0])" -for DarkYellow
                write-host "$($x[1])" -for DarkYellow
                write-host "$($x[2])" -for DarkYellow
                write-host "$($x[3])" -for DarkYellow
            }     
        return $loginObj      
    }

} #EndFunction
Function Start-VaultWeb                {
<#
    .Synopsis
        start-vaultweb  
    .DESCRIPTION
    start-vaultweb  wil run  C:\Program Files\Mozilla` Firefox\firefox.exe 
    .EXAMPLE 
    start-vaultweb  -APIAddress "http://127.0.0.1:8200"    
    start-vaultweb  -APIAddress "http://192.168.2.10:8200"           
#>    
  
[CmdletBinding()]

param(
    [Parameter(Mandatory=$true)]
    [string]$APIAddress 
)  

Begin{
    if(!(test-path "C:\Program Files\Mozilla` Firefox\firefox.exe")){
        Write-warning "[error] : could not find firefox.exe (C:\Program Files\Mozilla` Firefox\firefox.exe)" ;
        break        
    }
}

Process{
    #Start firefox with API Adresss
    C:\Program` Files\Mozilla` Firefox\firefox.exe $APIAddress
    
}

End{}
    
} #EndFunction

Function Stop-VaultTask                {
    <#
    .Synopsis
    start-vaulttask
    .DESCRIPTION
    start-vaulttask will start vault by starting the scheduled task
    .EXAMPLE     
    start-vaulttask -taskname "Hashicorp_Vault"     
    #>    
  
    [CmdletBinding()] 

    param(
        #Param help
        [Parameter(Mandatory=$false)]
        $Taskname = "Hashicorp_Vault"
    )

    process{

        If((Get-ScheduledTask -TaskName $taskname).state -eq "running"){
            stop-ScheduledTask  -TaskName  $taskname -Verbose
        }#EndIf

        write-host "  Stopping task , please wait : " -NoNewline
        write-host " " -NoNewline -BackgroundColor yellow

        do{
            sleep 1 ; write-host " " -NoNewline -BackgroundColor Yellow
        }until ((Get-ScheduledTask -TaskName $taskname).state -eq "ready")
        
        write-host "  -> Stopped ($((Get-ScheduledTask -TaskName $taskname).state))" 
           
    }
} #EndFunction
Function Start-VaultTask               {
    <#
    .Synopsis
    stop-vaulttask
    .DESCRIPTION
    stop-vaulttask will stop vault by ending the scheduled task
    .EXAMPLE     
    stop-vaulttask -taskname "Hashicorp_Vault"     
    #>    
  
    [CmdletBinding()] 

    param(
        #Param help
        [Parameter(Mandatory=$false)]
        $Taskname = "Hashicorp_Vault"
    )

    process{

        If((Get-ScheduledTask -TaskName $taskname).state -eq "ready"){
            start-ScheduledTask  -TaskName  $taskname -Verbose
        }
        write-host "please wait : " -NoNewline
        write-host " " -NoNewline -BackgroundColor yellow
        do
        {
            sleep 1
            write-host " " -NoNewline -BackgroundColor Yellow
        }
        until ((Get-ScheduledTask -TaskName $taskname).state -eq "running")
        write-host "  -> $((Get-ScheduledTask -TaskName $taskname).state)" 
          
     
    }
} #EndFunction
Function Import-PSVaultModule          { 
    <#
    .Synopsis
    Import-PSVaultModule 
    .DESCRIPTION
    Import-PSVaultModule is only for testing
    .EXAMPLE     
    Import-PSVaultModule -path "$env:USERPROFILE\Downloads" -GitHttpsLink "https://github.com/D2CIT/Hashicorp-Vault.git"
             
    #> 
    param(
        #Download Module
        $path         = "$env:USERPROFILE\Downloads" ,
        $GitHttpsLink = "https://github.com/D2CIT/Hashicorp-Vault.git"
    )

    cd $path
    mkdir git
    cd git
    #Clone Git repo
    git clone $GitHttpsLink

    #copy to module folder
    copy -recurse "$path\Hashicorp-Vault\PSVault" -Destination "C:\Program Files\WindowsPowerShell\Modules"

    #remove downloaded repo
    remove-recurse $path\git
} #EndFunction 




Export-ModuleMember -Function *
