###########################################################################
#
# NAME: Privilege Cloud Prerequisites check
#
# AUTHOR:  Mike Brook
#
# COMMENT: 
# Script checks prerequisites for Privilege Cloud Connector machine
#
#
###########################################################################

 <#
  .DESCRIPTION
  Script checks prerequisites for Privilege Cloud Connector machine
  
  .PARAMETER OutOfDomain
  .PARAMETER POC
  .PARAMETER Troubleshooting
  .PARAMETER SkipVersionCheck
  .PARAMETER SkipIPCheck
 
  .EXAMPLE 
  PS C:\> .\PSMCheckPrerequisites.ps1
  
  .EXAMPLE - Run checks if machine is out of domain
  PS C:\> .\PSMCheckPrerequisites.ps1 -OutOfDomain

  .EXAMPLE - Troubleshoot certain components
  PS C:\> .\PSMCheckPrerequisites.ps1 -Troubleshooting
  
  .EXAMPLE - Run in POC mode
  PS C:\> .\PSMCheckPrerequisites.ps1 -POC

  .EXAMPLE - Skip Online Checks
  PS C:\> .\PSMCheckPrerequisites.ps1 -SkipVersionCheck -SkipIPCheck
  
#>
[CmdletBinding(DefaultParameterSetName="Regular")]
param(
	# Use this switch to Exclude the Domain user check
	[Parameter(ParameterSetName='Regular',Mandatory=$false)]
	[switch]$OutOfDomain,
	# Use this switch to run an additional tests for POC
	[Parameter(ParameterSetName='Regular',Mandatory=$false)]
	[switch]$POC,
	# Use this switch to troubleshoot specific items
	[Parameter(ParameterSetName='Troubleshoot',Mandatory=$false)]
	[switch]$Troubleshooting,
	# Use this switch to check CPM Install Connection Test
	[Parameter(ParameterSetName='CPMConnectionTest',Mandatory=$false)]
	[switch]$CPMConnectionTest,
    # Use this switch to skip online checks
    [Parameter(ParameterSetName='regular',Mandatory=$false)]
    [switch]$SkipVersionCheck,
    [Parameter(ParameterSetName='regular',Mandatory=$false)]
    [switch]$SkipIPCheck
)

# ------ SET Script Prerequisites ------
##############################################################

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

## List of checks to be performed on POC
$arrCheckPrerequisitesPOC = @("CheckTLS1")

## List of checks to be excluded when machine is out of domain
$arrCheckPrerequisitesOutOfDomain = @("DomainUser","PrimaryDNSSuffix") #PSM

## List of checks to be performed on every run of the script
$arrCheckPrerequisitesGeneral = @(
"VaultConnectivity", #General
"CustomerPortalConnectivity", #General
"OSVersion", #General
"Processors", #General
"Memory", #General
"InterActiveLoginSmartCardIsDisabled", #General
"UsersLoggedOn", #General
"KBs", #Obsolete
"IPV6", #General
"MachineNameCharLimit", #General
"NetworkAdapter", #General
"DotNet", #General
"PSRemoting", #General
"WinRM", #General
"WinRMListener", #General
"NoPSCustomProfile", #General
"PendingRestart", #General
"GPO" #General + PSM
)

$arrCheckPrerequisitesSecureTunnel = @(
"TunnelConnectivity", #SecureTunnel
"ConsoleNETConnectivity", #SecureTunnel
"ConsoleHTTPConnectivity", #SecureTunnel
"SecureTunnelLocalPort" #SecureTunnel
)


$arrCheckPrerequisitesPSM = @(
"CheckNoRDS", #PSM
"SQLServerPermissions", #PSM
"SecondaryLogon", #PSM
"KUsrInitDELL" #PSM
)

$arrCheckPrerequisitesCPM = @(
"CRLConnectivity" #CPM
)


## If not OutOfDomain then include domain related checks
If (-not $OutOfDomain){
	$arrCheckPrerequisitesPSM += $arrCheckPrerequisitesOutOfDomain
}
## Combine Checks from POC with regular checks
If ($POC){
	$arrCheckPrerequisitesGeneral += $arrCheckPrerequisitesPOC
}

$arrCheckPrerequisites = @{General = $arrCheckPrerequisitesGeneral},@{CPM = $arrCheckPrerequisitesCPM},@{PSM = $arrCheckPrerequisitesPSM},@{SecureTunnel = $arrCheckPrerequisitesSecureTunnel}


## List of GPOs to check
$arrGPO = @(
       [pscustomobject]@{Name='Require user authentication for remote connections by using Network Level Authentication';Expected='Not Configured'}
	   [pscustomobject]@{Name='Select RDP transport protocols'; Expected='Not Configured'}	
       [pscustomobject]@{Name='Use the specified Remote Desktop license servers'; Expected='Not Configured'}   
	   [pscustomobject]@{Name='Set client connection encryption level'; Expected='Not Configured'}
	   [pscustomobject]@{Name='Use Remote Desktop Easy Print printer driver first'; Expected='Not Configured'}
       [pscustomobject]@{Name='Allow CredSSP authentication'; Expected='Not Configured'}
       [pscustomobject]@{Name='Allow remote server management through WinRM'; Expected='Not Configured'}
       [pscustomobject]@{Name='Prevent running First Run wizard'; Expected='Not Configured'}
       [pscustomobject]@{Name='Allow Remote Shell Access'; Expected='Not Configured'}
       [pscustomobject]@{Name='Interactive logon: Require Smart card'; Expected='Not Configured'}
   )


##############################################################

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:PSMConfigFile = "_PSMCheckPrerequisites_PrivilegeCloud.ini"

# Script Version
[int]$versionNumber = "35"

# ------ SET Files and Folders Paths ------
# Set Log file path
$global:LOG_DATE = $(get-date -format yyyyMMdd) + "-" + $(get-date -format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\_PSMCheckPrerequisites_PrivilegeCloud.log"
$global:CONFIG_PARAMETERS_FILE = "$ScriptLocation\$PSMConfigFile"

# ------ SET Global Parameters ------
$global:g_ConsoleIPstd = "console.privilegecloud.cyberark.com"
$global:g_ConsoleIPispss = "console.privilegecloud.cyberark.cloud"
$global:g_ScriptName = "PSMCheckPrerequisites_PrivilegeCloud.ps1"
$global:g_CryptoPath = "C:\ProgramData\Microsoft\Crypto"

$global:table = ""
$SEPARATE_LINE = "------------------------------------------------------------------------" 
$g_SKIP = "SKIP"


#region Troubleshooting
Function Show-Menu{
    Clear-Host
    Write-Host "================ Troubleshooting Guide ================"
    
    Write-Host "1: Press '1' to Test LDAPS Bind Account" -ForegroundColor Green
    Write-Host "2: Press '2' to Enable TLS 1.0 (Only for POC)" -ForegroundColor Green
    Write-Host "3: Press '3' to Retrieve DC Info" -ForegroundColor Green
    Write-Host "4: Press '4' to Disable IPv6" -ForegroundColor Green
    Write-Host "5: Press '5' to Enable WinRM HTTPS Listener" -ForegroundColor Green
    Write-Host "6: Press '6' to Config WinRMListener Permissions" -ForegroundColor Green
    Write-Host "7: Press '7' to Enable SecondaryLogon Service" -ForegroundColor Green
    Write-Host "8: Press '8' to Run CPM Install Connection Test" -ForegroundColor Green
    Write-Host "Q: Press 'Q' to quit."
}
Function Troubleshooting{
Function Connect-LDAPS(){
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$false)][string] $hostname = (Read-Host -Prompt "Enter Hostname (eg; cyberarkdemo.com)"),
        [parameter(Mandatory=$false)][int] $Port = (Read-Host -Prompt "Enter Port($("636"))"),
        [parameter(Mandatory=$false)][string] $username = (Read-Host -Prompt "Enter Username (eg; svc_cyberark)")
    )
    
#$username = Read-Host "Bind Account Username (eg; svc_cyberark)"
#$hostname = Read-Host "DC server (eg; cyberarkdemo.com)"
#$Port = Read-Host "Port (eg; 636, 3269)"

if ($Port -eq 0){$port = 636}

$Null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
#Connects to LDAP
$LDAPConnect = New-Object System.DirectoryServices.Protocols.LdapConnection $HostName`:$Port

#Set session options (SSL + LDAP V3)
$LDAPConnect.SessionOptions.SecureSocketLayer = $true
$LDAPConnect.SessionOptions.ProtocolVersion = 3

# Pick Authentication type:
# Anonymous, Basic, Digest, DPA (Distributed Password Authentication),
# External, Kerberos, Msn, Negotiate, Ntlm, Sicily
$LDAPConnect.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic

# Gets username and password.
$credentials = new-object "System.Net.NetworkCredential" -ArgumentList $UserName,(Read-Host "Password" -AsSecureString)
# Bind with the network credentials. Depending on the type of server,
# the username will take different forms.
Try {
$ErrorActionPreference = 'Stop'
$LDAPConnect.Bind($credentials)
$ErrorActionPreference = 'Continue'
}
Catch {
Throw "Error binding to ldap  - $($_.Exception.Message)"
}


Write-LogMessage -Type Verbose -Msg "Successfully bound to LDAP!"
$basedn = "DC=cyberarkdemo,DC=com" # TODO: Get current domain name of the machine or request domain name
$scope = [System.DirectoryServices.Protocols.SearchScope]::Base
#Null returns all available attributes
$attrlist = $null
$filter = "(objectClass=*)"

$ModelQuery = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList $basedn,$filter,$scope,$attrlist

#$ModelRequest is a System.DirectoryServices.Protocols.SearchResponse
Try {
$ErrorActionPreference = 'Stop'
$ModelRequest = $LDAPConnect.SendRequest($ModelQuery) 
$ErrorActionPreference = 'Continue'
}
Catch {
Throw "Problem looking up model account - $($_.Exception.Message)"
}

$ModelRequest
}
Function EnableTLS1(){
	$TLS1ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
	$TLS1ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
	ForEach ($tlsPath in @($TLS1ClientPath, $TLS1ServerPath))
	{
		If(-not (Test-Path $tlsPath))
		{
			New-Item -Path $tlsPath -Force 
		}
		New-ItemProperty -Path $tlsPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
		if ((Get-ItemProperty $tlsPath).Enabled -eq 1)
		{
			Write-LogMessage -Type Success -Msg "Added $tlsPath\Enabled"
		}Else{
			Write-LogMessage -Type Warning -Msg "Couldn't add $tlsPath\Enabled"
		}
		New-ItemProperty -Path $tlsPath -Name "DisabledByDefault" -Value "0" -PropertyType DWORD -Force
		if ((Get-ItemProperty $tlsPath).DisabledByDefault -eq 0)
		{
			Write-LogMessage -Type Success -Msg "Added $tlsPath\DisabledByDefault"
		}Else{
			Write-LogMessage -Type Warning -Msg "Couldn't add $tlsPath\DisabledByDefault"
		}
	}
	
	Write-LogMessage -Type Success -Msg "Enabled TLS1.0!"
}
Function GetListofDCsAndTestBindAccount(){
$UserPrincipal = Get-UserPrincipal
if($UserPrincipal.ContextType -eq "Domain"){

function listControllers
{
$dclist = ""
$Domain = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().name
$dclist = netdom query /D:$Domain dc | Select-Object -SkipLast 2 | Select-Object -Skip 2 | ForEach-Object {"$_.$domain"}
return $dclist
}

function Test-LDAPPorts {
    [CmdletBinding()]
    param(
        [string] $ServerName,
        [int] $Port
    )

        Remove-Item "$PSScriptRoot\DCInfo.txt" -Force -ErrorAction SilentlyContinue

        try {
            $LDAP = "LDAP://" + $ServerName + ':' + $Port
            $Connection = [ADSI]($LDAP)
            $Connection.Close()
            return $true
        } catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Can't open $ServerName`:$Port."
            } elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
                Write-Warning "Current user ($Env:USERNAME) doesn't seem to have access to to LDAP on port $Server`:$Port"
            } else {
                Write-Warning -Message $_
            }
        }
        return $False
    }

Function Test-LDAP {
    [CmdletBinding()]
    param (
        [alias('Server', 'IpAddress')][Parameter(Mandatory = $False)][string[]]$ComputerName,
        [int] $GCPortLDAP = 3268,
        [int] $GCPortLDAPSSL = 3269,
        [int] $PortLDAP = 389,
        [int] $PortLDAPS = 636
    )

        if (!$ComputerName){
    $ComputerName = listControllers
    }

    # Checks for ServerName - Makes sure to convert IPAddress to DNS
    foreach ($Computer in $ComputerName) {
        [Array] $ADServerFQDN = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue)
        if ($ADServerFQDN) {
            if ($ADServerFQDN.NameHost) {
                $ServerName = $ADServerFQDN[0].NameHost
            } else {
                [Array] $ADServerFQDN = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue)
                $FilterName = $ADServerFQDN | Where-Object { $_.QueryType -eq 'A' }
                $ServerName = $FilterName[0].Name
            }
        } else {
            $ServerName = ''
        }
        $GlobalCatalogSSL = Test-LDAPPorts -ServerName $ServerName -Port $GCPortLDAPSSL -WarningAction SilentlyContinue
        $GlobalCatalogNonSSL = Test-LDAPPorts -ServerName $ServerName -Port $GCPortLDAP -WarningAction SilentlyContinue
        $ConnectionLDAPS = Test-LDAPPorts -ServerName $ServerName -Port $PortLDAPS -WarningAction SilentlyContinue
        $ConnectionLDAP = Test-LDAPPorts -ServerName $ServerName -Port $PortLDAP -WarningAction SilentlyContinue

        #if Variable holds $true then print it's port out and sort it in a table.
        $PortsThatWork = @(
            if ($GlobalCatalogNonSSL) { $GCPortLDAP }
            if ($GlobalCatalogSSL) { $GCPortLDAPSSL }
            if ($ConnectionLDAP) { $PortLDAP }
            if ($ConnectionLDAPS) { $PortLDAPS }
        ) | Sort-Object
        [pscustomobject]@{
            DomainController    = $Computer
            #ComputerFQDN       = $ServerName
            GlobalCatalogLDAP  = $GlobalCatalogNonSSL
            GlobalCatalogLDAPS = $GlobalCatalogSSL
            LDAP               = $ConnectionLDAP
            LDAPS              = $ConnectionLDAPS
            AvailablePorts     = $PortsThatWork -join ','
        }
    }
}
Write-Host -ForegroundColor Cyan "Outputting DC Info on screen, this will also be stored in local file `"DCInfo.txt`"."
Write-Host -ForegroundColor Cyan "This might take awhile depending on your network configuration."
Test-LDAP |format-table| Tee-Object -file "$PSScriptRoot\DCInfo.txt"
}Else{Write-Host "Must be logged in as domain member."}
}
Function DisableIPV6(){
    #Disable IPv6 on NIC
	Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

	#Disable IPv6 on Registry
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "0xFFFFFFFF" -PropertyType DWORD -Force

    Write-LogMessage -Type Success -Msg "Disabled IPv6, Restart machine to take affect."
}
Function EnableWinRMListener(){
Function Show-MenuWinRM{
    Clear-Host
    Write-Host "================ Configure WinRM ================"
    
    Write-Host "1: Press '1' to Unbind existing Cert (to start fresh)" -ForegroundColor Magenta
    Write-Host "2: Press '2' to Generate new Self-Signed Cert" -ForegroundColor Magenta
    Write-Host "3: Press '3' to Configure WinRM Listener with new Cert" -ForegroundColor Magenta
    Write-Host "4: Press '4' to Add Inbound FW Rule (WinRM HTTPS 5986)" -ForegroundColor Magenta
    Write-Host "5: Press '5' to Add Permissions" -ForegroundColor Magenta
    Write-Host "6: Press '6' to Run all steps (1-5) [Recommended]" -ForegroundColor Magenta 
    Write-Host "Q: Press 'Q' to quit."
}
Function RemoveCert(){
Write-Host "Unbinding existing cert from WinRM HTTPS listener..." -ForegroundColor Cyan
Try{
Remove-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTPS'; Address="*"}
}
Catch{}
Write-Host "Done!" -ForegroundColor Green
}


Function Add-newCert(){
Try{
#Generate new CERT
Write-Host "Generating new self signed certificate, only do this once!" -ForegroundColor Cyan
Write-Host "If you want to repeat this action, please manually delete the cert first to avoid clutter." -ForegroundColor Cyan
$newCert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
$global:newCert = $newCert
Write-Host "Done!" -ForegroundColor Green
}
Catch
{
"Error: $(Collect-ExceptionMessage $_.Exception)"
}
}
Function ConfigWinRMList(){
#Configure WinRM Listener with the new Cert
Try{
Write-Host "Configuring WinRM with HTTPS Listener, you can check later by typing 'Winrm e winrm/config/listener'" -ForegroundColor Cyan
New-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTPS'; Address="*"} -ValueSet @{Hostname="$env:COMPUTERNAME";CertificateThumbprint=$newCert.Thumbprint} > $null 2>&1
Set-WSManInstance -ResourceURI winrm/config/service -ValueSet @{CertificateThumbprint=$newCert.Thumbprint} > $null 2>&1 #set the cert on the service level aswell.
Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force #Allow TrustedHosts

#Check if HTTP 5985 is missing and add it aswell (in case user accidently deleted it, its required since RD Connection broker uses HTTP when adding role).
Try{
Get-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTP'; Address="*"} > $null 2>&1
}
Catch [System.Management.Automation.RuntimeException]
{
if (($_.Exception.Message) -like "*The service cannot find the resource identified*"){
New-WSManInstance winrm/config/Listener -SelectorSet @{Transport='HTTP'; Address="*"}
}
}
Write-Host "Done!" -ForegroundColor Green
Write-Host @"
Some Useful Commands:

[To delete the HTTPS Listener manually]:
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS

[To Check the configuration manually]:
Winrm e winrm/config/listener
and
Winrm get winrm/config

[To perform manual connect]:
Connect-WSMan -ComputerName <ComputerIPHere>

"@ -ForegroundColor Green
}
Catch
{
#"Error: $(Collect-ExceptionMessage $_.Exception)"
"Error: $($_.Exception)"
}
}
Function Add-FWWinRMHTTPS(){
#Add FW Rule
Try{
Write-Host "Adding local FW inbound rule, port 5986" -ForegroundColor Cyan
netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5986
Write-Host "Done!" -ForegroundColor Green
}
Catch
{
"Error: $(Collect-ExceptionMessage $_.Exception)"
}
}

do
 {
     Show-MenuWinRM
     $selection = Read-Host "Please select an option"
     switch($selection)
     {
         '1' {
              RemoveCert
             }
         '2' {
              Add-newCert
             }
         '3' {
              ConfigWinRMList
             }
         '4' {
              Add-FWWinRMHTTPS
             }
         '5' {
              WinRMListenerPermissions
             }
         '6' {
              RemoveCert
              Add-newCert
              ConfigWinRMList
              Add-FWWinRMHTTPS
              WinRMListenerPermissions
              }
     }
     pause
 }
 until ($selection -eq 'q')
 break
}
Function WinRMListenerPermissions(){
Write-Host "Will attempt to add 'NETWORK SERVICE' user read permission for the WinRM HTTPS Certificate"
$winrmListen = Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{address="*";Transport="HTTPS"} -ErrorAction Stop

#Get Cert permissions
$getWinRMCertThumb = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq ($winrmListen.CertificateThumbprint)}
$rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($getWinRMCertThumb)
$filename = $rsaCert.key.uniquename

if (Test-Path -Path "$g_CryptoPath\Keys\$filename"){
$certkeypath = "$g_CryptoPath\Keys\$filename"}
Else{
$certkeypath = "$g_CryptoPath\RSA\MachineKeys\$filename"
}


$certPermissions =  Get-Acl -Path $certkeypath

#Set Cert permissions
$newRule = New-Object Security.accesscontrol.filesystemaccessrule "NETWORK SERVICE", "read", allow
$certPermissions.AddAccessRule($newRule)
Set-Acl -Path $certkeypath -AclObject $certPermissions
$certPermissions =  Get-Acl -Path $certkeypath

If ($certPermissions.Access.IdentityReference -contains "NT AUTHORITY\NETWORK SERVICE"){
Write-Host ""
Write-Host "Success!" -ForegroundColor Green
Write-Host "Review the changes:" -ForegroundColor Green
Write-Host $certPermissions.Access.IdentityReference -Separator `n
Write-Host ""
}
Else{
Write-Host "Something went wrong, You'll have to do it manually :(" -ForegroundColor Red
Write-Host "Launch MMC -> Certificates -> Find the cert WinRM is using -> Right Click -> All Tasks -> Manage Private Keys -> Grant 'NETWORK SERVICE' read permissions"
}


}
Function EnableSecondaryLogon(){

$GetSecondaryLogonService = Get-Service -Name seclogon
$GetSecondaryLogonServiceStatus = Get-Service -Name seclogon | select -ExpandProperty status
$GetSecondaryLogonServiceStartType = Get-Service -Name seclogon | select -ExpandProperty starttype

If (($GetSecondaryLogonServiceStartType -eq "Disabled") -or ($GetSecondaryLogonServiceStartType -eq "Manual")){
Get-Service seclogon | Set-Service -StartupType Automatic
}

$GetSecondaryLogonService | Start-Service
$GetSecondaryLogonService.WaitForStatus('Running','00:00:05')
$GetSecondaryLogonServiceStatus = Get-Service -Name seclogon | select -ExpandProperty status

if($GetSecondaryLogonServiceStatus -eq "Running"){
    Write-LogMessage -Type Success -Msg "Successfully started Secondary Logon Service!"
}
Else{
    Write-LogMessage -Type Warning -Msg "Something went wrong, do it manually :("
    }
}
Function CPMConnectionTestFromTroubleshooting(){
$CPMConnectionTest = $true
CPMConnectionTest
}

do
 {
     Show-Menu
     $selection = Read-Host "Please select an option"
     switch ($selection)
     {
         '1' {
              Connect-LDAPS
             }
         '2' {
              EnableTLS1
             }
         '3' {
              GetListofDCsAndTestBindAccount
             }
         '4' {
              DisableIPV6
             }
         '5' {
              EnableWinRMListener
             }
         '6' {
              WinRMListenerPermissions
             }
         '7' {
              EnableSecondaryLogon
             }
         '8' {
              CPMConnectionTestFromTroubleshooting
             }  
     }
     pause
 }
 until ($selection -eq 'q')
 exit
}
#endregion

#region Find Components
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
Function Get-ServiceInstallPath{
    param ($ServiceName)
    Begin
    {

    }
    Process
    {
        $retInstallPath = $Null
        try
        {
            if ($m_ServiceList -eq $null)
            {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
            }
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($regPath -ne $null)
            {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'), $regPath.ImagePath.LastIndexOf('"') + 1)
            }
        }
        catch
        {
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName", $_.Exception))
        }

        return $retInstallPath
    }
    End
    {

    }
}

#region Prerequisites methods
# @FUNCTION@ ======================================================================================================================
# Name...........: CheckNoRDS
# Description....: Check if RDS is installed before the connector is installed
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CheckNoRDS
{
	[OutputType([PsCustomObject])]
	param ()

    Write-LogMessage -Type Verbose -Msg "Starting CheckNoRDS..."

    $global:REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
    #If PSM is already installed, there is no need to run this check, since PSM can't be installed without RDS, we can assume RDS is installed.
    $global:m_ServiceList = $null
    if ($(Get-ServiceInstallPath $REGKEY_PSMSERVICE) -eq $null){
	    try{
	    	$errorMsg = ""
	    	$result = $True
	    	$actual = (Get-WindowsFeature Remote-Desktop-Services).InstallState -eq "Installed"
	    	If($actual -eq $True)
	    	{
	    		$result = $False
	    		$errorMsg = "RDS shouldn't be deployed before CyberArk is installed, remove RDS role and make sure there are no domain level GPO RDS settings applied (rsop.msc). Please note, after you remove RDS and restart you may need to use 'mstsc /admin' to connect back to the machine."
	    	}
	    } catch {
	    	$errorMsg = "Could not check RDS installation. Error: $(Collect-ExceptionMessage $_.Exception)"
	    }
    }
    Else{
    $result = $true
    $actual = $true
    $errorMsg = ""
    }

    Write-LogMessage -Type Verbose -Msg "Finished CheckNoRDS"
		
	return [PsCustomObject]@{
		expected = $False;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}      
}


# @FUNCTION@ ======================================================================================================================
# Name...........: PrimaryDNSSuffix
# Description....: Check if machine has Primary DNS Suffix configured
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function PrimaryDNSSuffix
{
	[OutputType([PsCustomObject])]
	param ()
		Write-LogMessage -Type Verbose -Msg "Starting PrimaryDNSSuffix..."
		$errorMsg = ""
		$result = $True
        $PrimaryDNSSuffix = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tcpip\Parameters | select -ExpandProperty Domain
		$actual = $PrimaryDNSSuffix -eq $env:userdnsdomain
		If($actual -eq $True)
		{
			$result = $True
		}
        else
        {
            $result = $False
            $errorMsg = "The logged in user domain: '$($env:userdnsdomain)' doesn't match the machine domain: '$PrimaryDNSSuffix'. Please see KB '000020063' on the customer support portal."
        }
		Write-LogMessage -Type Verbose -Msg "Finished PrimaryDNSSuffix"
		
	return [PsCustomObject]@{
		expected = $False;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}      
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CheckTLS1
# Description....: Check If TLS1 is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CheckTLS1
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting CheckTLS1..."
		$actual = ""
		$errorMsg = ""
		$result = $false
		
		if ($POC)
		{
			$TLS1ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
			$TLS1ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
			ForEach ($tlsPath in @($TLS1ClientPath, $TLS1ServerPath))
			{
				$chkEnabled = $chkDisabledByDefault = $false
				If(Test-Path $tlsPath)
				{
					$chkEnabled = ((Get-ItemProperty $tlsPath).Enabled -eq 1)
					$chkDisabledByDefault = ((Get-ItemProperty $tlsPath).DisabledByDefault -eq 0)
				}
				If($chkEnabled -and $chkDisabledByDefault)
				{
					$actual = $true
					$result = $true
				}
				Else
				{
					$actual = $false
					$result = $false
					$errorMsg = "TLS 1.0 needs to be enabled for POC, if you don't know how to, rerun the script with -Troubleshooting flag"
					break
				}
			}
		}
		Write-LogMessage -Type Verbose -Msg "Finished CheckTLS1"
	} catch {
		$errorMsg = "Could not check if TLS is enabled. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	} 
}

# @FUNCTION@ ======================================================================================================================
# Name...........: OSVersion
# Description....: Check the required local machine OS version
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function OSVersion
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting OSVersion..."
		$actual = (Get-WmiObject Win32_OperatingSystem).caption
		$errorMsg = ""
		$result = $false
		
		If($actual -Like '*2016*' -or $actual -like '*2019*')
		{
			$result = $true
		}
		elseif($actual -Like '*2012 R2*')
		{
			$errorMsg = "Privileged Cloud installation must be run on Windows Server 2016/2019."   
			$result = $true   
		}
		else
		{
			$result = $false
		}
		Write-LogMessage -Type Verbose -Msg "Finished OSVersion"
	} catch {
		$errorMsg = "Could not get OS Version. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "Windows Server 2016/2019";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: NetworkAdapter
# Description....: Check if all network adapters are Up
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function NetworkAdapter
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting NetworkAdapter..."
		$actual = ""
		$result = $false
		$errorMsg = ""

		$actual = (Get-NetAdapter | Where-Object status -ne "Up")
		if ($actual)
		{
			$errorMsg = "Not all NICs are up, the installer requires it (you can disable it again afterwards)."
			$actual = $true
		}
		else
		{
			$actual = $false
			$result = $true
		}
		Write-LogMessage -Type Verbose -Msg "Finished NetworkAdapter"
	} catch {
		$errorMsg = "Could not get Network Adapter Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "False";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: IPv6
# Description....: Check if IPv6 is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function IPV6
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting IPv6..."
		$actual = ""
		$result = $false
		$errorMsg = ""
	
		$arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress
		$IPv6Status = ($arrInterfaces | Where-Object { $_.contains("::") }).Count -gt 0

		if($IPv6Status)
		{
			$actual = "Enabled"
			$result = $false
            $errorMsg = "Disable IPv6, You can rerun the script with -Troubleshooting flag to do it."
		}
		else 
		{
			$actual = "Disabled"
			$result = $true
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished IPv6"
	} catch {
		$errorMsg = "Could not get IPv6 Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "Disabled";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Secondary Logon
# Description....: Check if Secondary Logon Service is running
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SecondaryLogon
{
	[OutputType([PsCustomObject])]
	param ()

		Write-LogMessage -Type Verbose -Msg "Starting SecondaryLogon..."
		$actual = ""
		$result = $false
		$errorMsg = ""
	
		$actual = (Get-Service -Name seclogon | select -ExpandProperty Status) -eq 'Running'

		If($actual -eq $True)
		{
			$result = $actual
			
		}
		else 
		{
			$actual = $actual
			$result = $actual
            $errorMsg = "Make sure 'Secondary Logon' Service is running, it is required for PSMShadowUsers to invoke Apps/WebApps. You can do it by rerunning the script with -Troubleshooting flag and selecting 'Enable SecondaryLogon Service'"
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished SecondaryLogon"

	return [PsCustomObject]@{
		expected = "True";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: KUsrInitDELL
# Description....: Check if the file KUsrInit.exe exists, indicating Dell Agent was deployed, Meaning Applocker need to whitelist it. 
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function KUsrInitDELL
{
	[OutputType([PsCustomObject])]
	param ()

		Write-LogMessage -Type Verbose -Msg "Starting KUsrInitDELL..."
		$actual = ""
		$result = $false
		$errorMsg = ""
	
		$actual = Test-Path C:\Windows\System32\KUsrInit.exe

		If($actual -eq $True)
		{
			$result = $actual
			$errorMsg = "File C:\Windows\System32\KUsrInit.exe detected! This means DELL agent is deployed and replaced the default UserInit file, you will need to remember to whitelist this file after installation in the PSM Applocker settings. This error will act as a reminder, if you want the script to ignore it, edit the $PSMConfigFile and put 'disabled' under KUsrInit."
            $KUsInit = 'true'
            $parameters = Import-CliXML -Path $CONFIG_PARAMETERS_FILE            
            if (-not($parameters.contains("KUsrInit"))){ #if doesn't contain the value, then we delete existing file and create new 
            Remove-Item -Path $CONFIG_PARAMETERS_FILE
            $parameters += @{KUsrInit = $KUsInit}
            $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII -Force
            }
            #If user changed the value manually in the file to false, we stop bugging him about this error.
            if($parameters.KUsrInit -eq "disabled"){
            $actual = $false
            $result = $true
            $errorMsg = ''
            }
            
		}
		else 
		{
			$actual = $actual
			$result = $true
            
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished KUsrInitDELL"

	return [PsCustomObject]@{
		expected = "false";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: DotNet
# Description....: Check if DotNet 4.8 or higher is installed.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
function DotNet()
{
	[OutputType([PsCustomObject])]
	param ()

	Write-LogMessage -Type Verbose -Msg "Starting DotNet..."
	$minimumDotNetVersionSupported = '528040'
    $expected = ".Net 4.8 is installed"
    $actual = ".Net 4.8 is not installed"
    $result = $false
    $errorMsg = ''

    try 
	{	
		# Read the .NET release version form the registry
		$dotNetRegKey = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
		
		# Check if the version is greater than the minium supported (if the Release key is not avilable , it's less than 4.5)
		if (($dotNetRegKey.Release -eq $null) -or ($dotNetRegKey.Release -lt $minimumDotNetVersionSupported))
		{		
			$actual = ".NET 4.8 is not installed"
            $result = $false
            $errorMsg = ".NET 4.8 or higher is needed for version 12.1+ of CPM/PSM, download it from https://go.microsoft.com/fwlink/?linkid=2088631"
		}
		else
		{
			$actual = $expected
			$result = $true
		}
	}
    catch
	{
		$actual = ".NET 4.8 is not installed"
		$result = $false
	}
    
		Write-LogMessage -Type Verbose -Msg "Finished DotNet"

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}	


# @FUNCTION@ ======================================================================================================================
# Name...........: PSRemoting
# Description....: Check if PSRemoting is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function PSRemoting
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting PSRemoting..."
		$actual = ""	
		$result = $false
		$errorMsg = ""
		If($(Test-WSMan -ComputerName "localhost" -ErrorAction SilentlyContinue))
		{
			try 
			{
				Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock { ; } -ErrorAction Stop | out-null
				$actual = "Enabled"	
				$result = $true
			} 
			catch 
			{
				$actual = "Disabled"
				$result = $false
				
				$UserMemberOfProtectedGroup = $(Get-UserPrincipal).GetGroups().Name -match "Protected Users"
				if ($UserMemberOfProtectedGroup)
				{
					$errorMsg = "Current user was detected in 'Protected Users' group in AD, remove from group."
				}
				else
				{
					$errorMsg = "Could not connect using PSRemoting to $($env:COMPUTERNAME), Error: $(Collect-ExceptionMessage $_.exception.Message)"
				}
			}
		} Else {
			$actual = "Disabled"
			$result = $false
			$errorMsg = "Run 'winrm quickconfig' to analyze root cause"
		}
		Write-LogMessage -Type Verbose -Msg "Finished PSRemoting"	
	} catch {
		$errorMsg = "Could not get PSRemoting Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "Enabled";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: WinRM
# Description....: Check if WinRM is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function WinRM
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting WinRM..."
		$actual = ""	
		$result = $false
		$errorMsg = ""
		$WinRMService = (Get-Service winrm).Status -eq "Running"
		Start-sleep 1

		if ($WinRMService)
		{
				#Force the output to be in English in case this is ran on non EN OS.
                [Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
                [CultureInfo]::CurrentUICulture = 'en-US'
			if ($getCRredSSP = ((Get-WSManCredSSP) -like "*This computer is not configured*"))
			{
				try {
					Enable-WSManCredSSP -Role Server -Force  | Out-Null
				} catch {
					if ($_.Exception.Message -like "*The config setting CredSSP cannot be changed because is controlled by policies*")
					{
						$errorMsg = "Can't Enable-WSManCredSSP, enforced by GPO."
					}
					Else
					{
						$errorMsg = $_.Exception.Message
					}
					$actual = $false
					$result = $actual
			   }
			}
			else
			{
			   $actual = (Get-Item -Path "WSMan:\localhost\Service\Auth\CredSSP").Value
			   if ($actual -eq $true){$result = "True"}
			}
		}
		else 
		{
			$errorMsg = "Verify WinRM service is running"
		}
	
		Write-LogMessage -Type Verbose -Msg "Finished WinRM"	
	} catch {
		$errorMsg = "Could not get WinRM Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "True";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: WinRMListener
# Description....: Check if WinRM is listening on the correct protocal and port
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function WinRMListener
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting WinRMListener..."
		$actual = ""
		$result = $false
		$errorMsg = ""

        $winrmListen = Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{address="*";Transport="HTTPS"} -ErrorAction Stop
		if ($winrmListen.Transport -eq "HTTPS" -and $winrmListen.Enabled -eq "true")
		{
              #Get Cert permissions
              $getWinRMCertThumb = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq ($winrmListen.CertificateThumbprint)}
              $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($getWinRMCertThumb)
              $filename = $rsaCert.key.uniquename

              #Check where Key is stored since it can be in two places
              if (Test-Path -Path "$g_CryptoPath\Keys\$filename"){
              $certkeypath = "$g_CryptoPath\Keys\$filename"}
              else{
              $certkeypath = "$g_CryptoPath\RSA\MachineKeys\$Filename"
              }
              $certPermissions =  Get-Acl -Path $certkeypath
              If ($certPermissions.Access.IdentityReference -contains "NT AUTHORITY\NETWORK SERVICE")
              {
			  $actual = $true
			  $result = $True
              }
              Else
              {
              $actual = "Empty"
			  $result = $false
			  $errorMsg = "WinRM HTTPS Cert doesn't have correct permissions (NETWORK SERVICE user needs 'read' permission, adjust this manually, if you don't know how, rerun the script with -Troubleshooting flag and select 'WinRMListenerPermissions'"
              }
            #Add Another IF, after successful check for HTTPs, check the thumbprint of the cert, and see if NETWORK SERVICE user has access to it (just read permission).
		} 
		else 
		{
			  $actual = "Empty"
			  $result = $false
			  $errorMsg = "WinRM Listener isn't receiving on HTTPS, check it with the following command 'Winrm e winrm/config/listener' in ps"
		}

		Write-LogMessage -Type Verbose -Msg "Finished WinRMListener"
	} catch {
        $errorMsg = "WinRM Listener isn't receiving on HTTPS, check it with the following command 'Winrm e winrm/config/listener' in ps, you can also rerun the script with -Troubleshooting flag to configure it"
		#$errorMsg = "Could not check WinRM Listener Port. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: NoPSCustomProfile
# Description....: Check if there is no PowerShell custom profile
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
function NoPSCustomProfile
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting NoPSCustomProfile..."
		$actual = ""
		$errorMsg = ""
		$result = $true

		$profileTypes = "AllUsersAllHosts","AllUsersCurrentHost","CurrentUserAllHosts","CurrentUserCurrentHost"

		ForEach($profiles in $profileTypes)
		{
			if (Test-Path -Path $profile.$profiles)
			{
				$errorMsg = "Custom powershell profile detected, unload it from Windows and restart PS instance."
				$result = $false
				break
			}
		}
		Write-LogMessage -Type Verbose -Msg "Finished NoPSCustomProfile"	
	} catch {
		$errorMsg = "Could not get PowerShell custom profile Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "False";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: KBs
# Description....: Check if all relevant KBs are installed
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function KBs
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting KBs..."
		$actual = ""
		$errorMsg = ""
		$otherOS = $false
		$result = $false

		$hotFixes = ""
		$osVersion = [System.Environment]::OSVersion.Version
		
		if ($osVersion.Major -eq 10)
		{
			# currently there are no KBs to check on win 2016
			$hotFixes = ""
		}
		elseif (($osVersion.Major -eq 6) -And ($osVersion.Minor -eq 3) -And ($osVersion.Build -eq 9600))
		{
			$hotFixes = @('KB2919355','KB3154520')
		}
		else
		{
			$otherOS = $true
			$result = $true		
		}
		
		if (!$otherOS)
		{
			if($hotFixes -eq "")
			{
				$errorMsg = $g_SKIP
				$result =  $true
			}
		 
			else
			{
				$pcHotFixes = Get-HotFix $hotFixes -EA ignore | Select-Object -Property HotFixID 
		
				#none of the KBs installed
				if($null -eq $pcHotFixes)
				{
					$errorMsg = "KBs not installed: $hotFixes"
					$actual = "Not Installed"
					$result = $false
				}

				else
				{	
					$HotfixesNotInstalled = $hotFixes | Where-Object { $_ -notin $pcHotFixes }
		
					if($HotfixesNotInstalled.Count -gt 0)
					{			
						$errorMsg = "KBs not installed: $($HotfixesNotInstalled -join ',')"
						$actual = "Not Installed"
						$result = $false
					}
					else
					{
						$actual = "Installed"
						$result = $true
					}
				}
			}
		}

		Write-LogMessage -Type Verbose -Msg "Finished KBs"
	} catch {
		$errorMsg = "Could not get Installed KBs. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "Installed";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ServerInDomain
# Description....: Check if the server is in Domain or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ServerInDomain
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting ServerInDomain..."
		$result = $false
    
		if ((Get-WmiObject win32_computersystem).partofdomain) 
		{
			  $actual = "In Domain"
			  $result = $true
		} 
		else 
		{
			  $actual = "Not in Domain"
			  $result = $false
		}

		Write-LogMessage -Type Verbose -Msg "Finished ServerInDomain"
	} catch {
		$errorMsg = "Could not verify if server is in Domain. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "In Domain";
		actual = $actual;
		errorMsg = "";
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: DomainUser
# Description....: Check if the user is a Domain user
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function DomainUser
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting DomainUser..."
		$result = $false
		
		if ($OutOfDomain) 
		{
			$errorMsg = $g_SKIP
			$result = $true
		}
		else
		{
            
            Try{
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
			    $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
                if($UserPrincipal.ContextType -eq "Domain"){
                    $errorMsg = ''
				    $actual = "Domain user"
				    $result = $true
			}
			else 
			{
				$actual = $false
				$result = $false
                $errorMsg = "Not Domain User"
			}
}
            Catch{
            $result = $false
            $errorMsg = $_.Exception.InnerException.Message
            $actual = $false
            }
		}

		Write-LogMessage -Type Verbose -Msg "Finished DomainUser"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "Domain User";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PendingRestart
# Description....: Check if the machine has pending restarts
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function PendingRestart
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting PendingRestart..."
		$actual = ""
		$result = $false

		$regComponentBasedServicing = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' | Where-Object { $_.Name -contains "RebootPending" })
		$regWindowsUpdate = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' | Where-Object { $_.Name -contains "RebootRequired" })
		$regSessionManager = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations' -ErrorAction Ignore)
		$wmiClientUtilities = (Invoke-WmiMethod -Namespace "Root\CCM\ClientSDK" -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Ignore).RebootPending
		
		$chkComponentBasedServicing = ($null -eq $regComponentBasedServicing) -and ($regComponentBasedServicing -eq $true)
		$chkWindowsUpdate =	($null -eq $regWindowsUpdate) -and ($regWindowsUpdate -eq $true)
		$chkSessionManager = ($null -eq $regSessionManager) -and ($regSessionManager -eq $true)
		$chkClientUtilities = ($null -eq $wmiClientUtilities) -and ($wmiClientUtilities -eq $true)
		
		if ($chkComponentBasedServicing -or $chkWindowsUpdate -or $chkSessionManager -or $chkClientUtilities)
		{
			$actual = "Pending restart"
			$result = $False
		}		
		else
		{
			$actual = "Not Pending restart"
			$result = $True
		}
	
		Write-LogMessage -Type Verbose -Msg "Finished PendingRestart"
	} catch {
		$errorMsg = "Could not check pending restart on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = "Not pending restart";
		actual = $actual;
		errorMsg = "";
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: UsersLoggedOn
# Description....: Check how many users are connected to the machine
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function UsersLoggedOn
{
	[OutputType([PsCustomObject])]
	param ()
    $actual = ""
    $errorMsg = ""
    $result = $false
        
	try{
		Write-LogMessage -Type Verbose -Msg "Starting UsersLoggedOn..."
		
		$numOfActiveUsers = (query.exe user /server $($env:COMPUTERNAME) | select-object -skip 1 | measure).Count

		if($numOfActiveUsers -gt 1)
		{
			$actual = $numOfActiveUsers
			$errorMsg = "Check how many users logged on through Task Manager"
			$result = $False
		}
		else
		{
			$actual = "1"
			$result = $True
		}
	}catch{
		Write-LogMessage -Type Error -Msg "Cannot check if another user is logged on"
		$errorMsg = $g_SKIP
		$result = $false
	}
	
	Write-LogMessage -Type Verbose -Msg "Finished UsersLoggedOn"
	
    return [PsCustomObject]@{
        expected = "1";
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}	

# @FUNCTION@ ======================================================================================================================
# Name...........: GPO
# Description....: Check the GPOs on the machine
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function GPO
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting GPO..."
		$actual = ""	
		$errorMsg = ""
		$result = $false
		$gpoResult = $false
		$compatible = $true

		$path = "C:\Windows\temp\GPOReport.xml"
		gpresult /f /x $path *> $null

		[xml]$xml = Get-Content $path
		$RDSGPOs = $xml.Rsop.ComputerResults.ExtensionData.extension.policy | Where-Object { ($_.Category -match "Windows Components") }
		if($RDSGPOs.Count -gt 0)
		{
			ForEach($item in $RDSGPOs)
			{
				$skip = $false
				$name = "GPO: $($item.Name)"
				$errorMsg = ""	
				# Check if GPO exists in the critical GPO items
				If($arrGPO -match $item.name)
				{
					$expected = $($arrGPO -match $item.name).Expected
					$gpoResult = ($Expected -eq $($item.state))
					if(-not $gpoResult )
					{
						$compatible = $false
						$errorMsg = "Expected:"+$Expected+" Actual:"+$($item.state)
					}
				}
				# Check if GPO exists in RDS area
				elseif($item.Category -match "Remote Desktop Services")
				{
					$expected = 'Not Configured'
					$compatible = $false
					$errorMsg = "Expected:'Not Configured' Actual:"+$($item.state)
				}
				else {
					$skip = $true
				}
				if(!$skip)
				{
					Write-LogMessage -Type Verbose -Msg ("{0}; Expected: {1}; Actual: {2}" -f $name, $Expected, $item.state)
					$reportObj = @{expected = $expected; actual = $($item.state); errorMsg = $errorMsg; result = $gpoResult;}
					AddLineToTable $name $reportObj
				}
			}		
		}

		$errorMsg = $g_SKIP
		if(!$compatible)
		{
			 $actual = "Not Compatible"
			 $result = $false
		}
		else
		{
		   $result = $true
		}
	} catch {
		$errorMsg = "Could not check GPO settings on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = "PSM Compatible";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: VaultConnectivity
# Description....: Vault network connectivity on port 1858
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function VaultConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Runing VaultConnectivity"
    $script:VaultConnectivityOK = $false
	return Test-NetConnectivity -ComputerName $VaultIP -Port 1858
}

# @FUNCTION@ ======================================================================================================================
# Name...........: TunnelConnectivity
# Description....: Tunnel network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function TunnelConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Running TunnelConnectivity"
    return Test-NetConnectivity -ComputerName $TunnelIP -Port 443
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleNETConnectivity
# Description....: Privilege Cloud network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ConsoleNETConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Running ConsoleNETConnectivity"
	return Test-NetConnectivity -ComputerName $g_ConsoleIP -Port 443
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleHTTPConnectivity
# Description....: Privilege Cloud network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ConsoleHTTPConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting ConsoleHTTPConnectivity..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		
		$CustomerGenericGET = 0
		Try{
			$connectorConfigURL = "https://$g_ConsoleIP/connectorConfig/v1?customerId=$CustomerId&configItem=environmentFQDN"
			$CustomerGenericGET = Invoke-RestMethod -Uri $connectorConfigURL -TimeoutSec 20 -ContentType 'application/json'
			If($null -ne $CustomerGenericGET.config)
			{
				$actual = "200"
				$result = $true
			}
		} catch {
			if ($_.Exception.Message -eq "Unable to connect to the remote server")
			{
				$errorMsg = "Unable to connect to the remote server - Unable to GET to '$connectorConfigURL'"
				$result = $false
			}
			elseif ($_.Exception.Message -eq "The underlying connection was closed: An unexpected error occurred on a receive.")
			{
				$errorMsg = "The underlying connection was closed - Unable to GET to '$connectorConfigURL'"
				$result = $false
			}
            elseif ($_.Exception.Response.StatusCode.value__ -eq 404)
			{
				$actual = $true
				$result = $true
			}
			else
			{
				Throw $_
			}
		}		
		
		Write-LogMessage -Type Verbose -Msg "Finished ConsoleHTTPConnectivity"
	} catch {
		$errorMsg = "Could not verify console connectivity. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "200";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleHTTPConnectivity
# Description....: Privilege Cloud network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SecureTunnelLocalPort
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting SecureTunnelLocalPort..."
		$actual = ""
		$result = $false
		$errorMsg = ""
        $expected = "Empty"
		
		$lclPort = Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 50000 -or $_.LocalPort -eq 50001}
		if ($lclPort -eq $null)
		{
			  $actual = $expected
			  $result = $True
		}
        ElseIf((get-process -Id ($lclport).OwningProcess).ProcessName -eq "PrivilegeCloudSecureTunnel"){
              $result = $True
        }
		else 
		{
			  $actual = (get-process -Id ($lclport).OwningProcess).ProcessName
			  $result = $false
			  $errorMsg = "LocalPort 50000/50001 is taken by --> " + (get-process -Id ($lclport).OwningProcess).ProcessName + " <-- This port is needed for SecureTunnel functionality, if you're not going to install it you can disregard this error, otherwise we suggest checking what process is using it"
		}

		Write-LogMessage -Type Verbose -Msg "Finished SecureTunnelLocalPort"
	} catch {
		$errorMsg = "Could not check LocalPorts. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CRLConnectivity
# Description....: CRL connectivity
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CRLConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting CRLConnectivity..."
		$actual = ""
		$result = $false
		$errorMsg = ""

		$cert = 0


			$cert = Invoke-WebRequest -Uri http://ocsp.digicert.com -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing  | Select-Object -ExpandProperty StatusCode

			If($cert -eq 200)
			{
				$actual = "200"
				$result = $true
            }

		Write-LogMessage -Type Verbose -Msg "Finished CRLConnectivity"
	} catch {
		$errorMsg = "Could not verify CRL connectivity, Check DNS/FW. Error: $(Collect-ExceptionMessage $_.Exception.Message)"
	}
		
	return [PsCustomObject]@{
		expected = "200";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CustomerPortalConnectivity
# Description....: Privilege Cloud Console network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CustomerPortalConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Starting CustomerPortalConnectivity"

    return Test-NetConnectivity -ComputerName $PortalURL -Port 443
    Write-LogMessage -Type Verbose -Msg "Finished CustomerPortalConnectivity"
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Processors
# Description....: Minimum required CPU cores
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function Processors
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting Processors..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		
		$cpuNumber = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
		if ($cpuNumber -ge "8")
		{
			  $actual = $cpuNumber
			  $result = $True
		} 
		else 
		{
			  $actual = $cpuNumber
			  $result = $false
			  $errorMsg = "Less than minimum (8) cores detected"
		}

		Write-LogMessage -Type Verbose -Msg "Finished Processors"
	} catch {
		$errorMsg = "Could not check minimum required Processors. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Memory
# Description....: Minimum required Memory
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function Memory
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting Memory..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		$Memory = Try{[math]::Round(((Get-CimInstance CIM_PhysicalMemory).Capacity | Measure-Object -Sum).Sum / 1GB, 2)}Catch{}
		$MemoryAWS = Try{[math]::Round((Get-CimInstance -ClassName CIM_ComputerSystem).TotalPhysicalMemory / 1GB, 0)}Catch{}

		if ($Memory -ge 8 -or $MemoryAWS -ge 8)
		{
			  $actual = $Memory
			  $result = $True
		} 
		else 
		{
			  $actual = $Memory
			  $result = $false
			  $errorMsg = "Less than minimum (8) RAM detected"
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished Memory"
	} catch {
		$errorMsg = "Could not check minimum required memory. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}	

# @FUNCTION@ ======================================================================================================================
# Name...........: SQLServerPermissions
# Description....: Required SQL Server permissions
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SQLServerPermissions
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting SQLServerPermissions..."
		$actual = ""
		$result = $False
		$errorMsg = ""

		$SecPolGPO = @{
			"SeDebugPrivilege" = "Debug Programs";
			"SeBackupPrivilege" = "Back up files and directories";
			"SeSecurityPrivilege" = "Manage auditing and security log";
		}

		$path = "C:\Windows\Temp\SecReport.txt"
		SecEdit /areas USER_RIGHTS /export /cfg $path

		ForEach ($sec in $SecPolGPO.Keys) 
		{
			Write-LogMessage -Type Verbose -Msg "Checking $sec group policy for Local Administrators access"
			$administrators = Select-String $path -Pattern $sec
			if($null -eq $administrators)
			{
				Write-LogMessage -Type Verbose -Msg "No Local Administrators access for $sec group policy"
				$actual = $result = $False
				$errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
			}
			else
			{
				foreach ($admin in $administrators)
				{
					if ($admin -like "*S-1-5-32-544*")
					{
						Write-LogMessage -Type Verbose -Msg "$sec group policy has Local Administrators access"
						$actual = $True
                        $result = $True
					}
					else
					{
						Write-LogMessage -Type Verbose -Msg "No Local Administrators access for $sec group policy"
						$actual = $False
                        $result = $False
                        $errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
                        $missingGroup = $true
					}
                 # if even one of the groups was missing we need to declare final error as RED.
                 if($missingGroup){
                    $actual = $False
                    $result = $False
                 }
				}
			}
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished SQLServerPermissions"
	} catch {
		$errorMsg = "Could not check SQL Server permissions. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: LogonAsaService
# Description....: Logon as service permissions
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function LogonAsaService
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting LogonAsaService..."
		$actual = ""
		$result = $False
		$errorMsg = ""

		$SecPolGPO = @{
			"SeServiceLogonRight" = "Log on as a service";
		}

		$path = "C:\Windows\Temp\SecReport.txt"
		SecEdit /areas USER_RIGHTS /export /cfg $path

		ForEach ($sec in $SecPolGPO.Keys) 
		{
			Write-LogMessage -Type Verbose -Msg "Checking $sec group policy for access"
			$logonasAserviceUsers = Select-String $path -Pattern $sec
			if($null -eq $logonasAserviceUsers)
			{
				Write-LogMessage -Type Verbose -Msg "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
				$actual = $result = $False
				$errorMsg = "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
			}
			else
			{
				foreach ($logonUser in $logonasAserviceUsers)
				{
					if ($logonUser -like "*S-1-5-20*")
					{
						Write-LogMessage -Type Verbose -Msg "$sec group policy has access"
						$actual = $result = $True
					}
					else
					{
						Write-LogMessage -Type Verbose -Msg "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
						$actual = $result = $False
						$errorMsg = "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
					}
				}
			}
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished LogonAsaService"
	} catch {
		$errorMsg = "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: InterActiveLoginSmartCardIsDisabled
# Description....: Check that no smart card is required to RDP to the machine
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function InterActiveLoginSmartCardIsDisabled
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting InterActiveLoginSmartCardIsDisabled..."
		$actual = ""
		$result = $False
		$errorMsg = ""
        $expected = $true

		$secOptionspath = "C:\Windows\Temp\SecReport.txt"
		SecEdit /areas securitypolicy /export /cfg $secOptionspath | Out-Null

        $secOptionsValue = Get-Content $secOptionspath
		$SmartCardIsEnabled = $secOptionsValue | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,1'
        #if returns some value, it means its enabled (User will received CredSSP error during ansible install).
        if($SmartCardIsEnabled -ne $null){
            $result = $false
		    $errorMsg = "Please disable `"GPO: Interactive logon: Require Smart card`""
            $actual = $false
        }
        Else{
            $result = $True
		    $errorMsg = ""
            $actual = $True
        }
		
		Write-LogMessage -Type Verbose -Msg "Finished InterActiveLoginSmartCardIsDisabled"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

#endregion

#region Helper functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-NetConnectivity
# Description....: Network connectivity to a specific Hostname/IP on a specific port
# Parameters.....: ComputerName, Port
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function Test-NetConnectivity
{
	[OutputType([PsCustomObject])]
	param(
		[string]$ComputerName,
		[int]$Port
	)
	$errorMsg = ""
	$result = $False
	If(![string]::IsNullOrEmpty($ComputerName))
	{
		try{
			If(Get-Command Test-NetConnection -ErrorAction Ignore)
			{
				$retNetTest = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningVariable retWarning | Select-Object -ExpandProperty "TcpTestSucceeded"
				If($retWarning -like "*TCP connect to* failed" -or $retWarning -like "*Name resolution of*")
				{
					$errorMsg = "Network connectivity failed, check FW rules to '$ComputerName' on port '$Port' are allowed"
					$result = $False
				}
				Else { 
                     $result = $True
                     # if port 1858, indicating vault test, declate param so we can use it in CPMConnectionTest.
                     if($port -eq 1858){$script:VaultConnectivityOK = $True}
                     }
			}
			Else
			{
				# For OS with lower PowerShell version or Windows 2012
				$tcpClient = New-Object Net.Sockets.TcpClient
				$tcpClient.ReceiveTimeout = $tcpClient.SendTimeout = 2000;
				# We use Try\Catch to remove exception info from console if we can't connect
				try { 
					$tcpClient.Connect($ComputerName,$Port) 
					$retNetTest = $tcpClient.Connected
					if($retNetTest)
					{
						$tcpClient.Close()
						$result = $True
					}
					else
					{
						$errorMsg = "Network connectivity failed, check FW rules to '$ComputerName' on port '$Port' are allowed"
						$result = $False
					}
				} catch {}
			}
		} catch {
			$errorMsg = "Could not check network connectivity to '$ComputerName'. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}
	Else
	{
		$retNetTest = $False
		Write-LogMessage -Type Info -Msg "Skipping network test since host name is empty"
		$errorMsg = "Host name empty"
	}
	
	return [PsCustomObject]@{
		expected = $True;
		actual = $retNetTest;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-UserPrincipal
# Description....: Returns the Current User Principal object
# Parameters.....: None
# Return Values..: Current User Principal
# =================================================================================================================================
Function Get-UserPrincipal
{
	try { [System.DirectoryServices.AccountManagement] -as [type] }
	catch { Add-Type -AssemblyName System.DirectoryServices.AccountManagement }
	return [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
}

# @FUNCTION@ ======================================================================================================================
# Name...........: IsUserAdmin
# Description....: Check if the user is a Local Admin
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function IsUserAdmin()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
}

# @FUNCTION@ ======================================================================================================================
# Name...........: GetPublicIP
# Description....: Returns the public IP of the machine
# Parameters.....: None
# Return Values..: String, Public IP Address of local machine
# =================================================================================================================================
Function GetPublicIP()
{
	$PublicIP = ""

	try{
		Write-LogMessage -Type Info -Msg "Attempting to retrieve Public IP..." -Early
		$PublicIP = (Invoke-WebRequest -Uri ipinfo.io/ip -UseBasicParsing -TimeoutSec 5).Content
		$PublicIP | Out-File "$($env:COMPUTERNAME) PublicIP.txt"
		Write-LogMessage -Type Success -Msg "Successfully fetched Public IP: $PublicIP and saved it in a local file '$($env:COMPUTERNAME) PublicIP.txt'"
		return $PublicIP
	}
	catch{
		Write-LogMessage -Type Info -Msg "GetPublicIP: Couldn't grab Public IP for you, you'll have to do it manually: $(Collect-ExceptionMessage $_.Exception.Message)" -Early
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: MachineNameCharLimit
# Description....: Checks if Machine has name longer than 15 char MS limit.
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function MachineNameCharLimit()
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting MachineNameCharLimit..."
		$actual = ""
		$result = $False
		$errorMsg = ""
        $expected = $true

		[int]$MachineCharLength = (hostname).length
		
        
        #Check if machine name is over 15 chars.
        if($MachineCharLength -gt 15){
            $result = $false
		    $errorMsg = "Computer hostname is over 15 char limit."
            $actual = $MachineCharLength
        }
        Else{
            $result = $True
		    $errorMsg = ""
        }
		
		Write-LogMessage -Type Verbose -Msg "Finished MachineNameCharLimit"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Choice
# Description....: Prompts user for Selection choice
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function Get-Choice{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )
    if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1))
    {
        Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"
        exit
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = ""
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    #calculate width required based on longest option text and form title
    $minFormWidth = 300
    $formHeight = 44
    $minButtonWidth = 150
    $buttonHeight = 23
    $buttonY = 12
    $spacing = 10
    $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
    $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
    $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
    $spaceWidth = ($options.Count + 1) * $spacing
    $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
    $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
    $index = 0
    #create the buttons dynamically based on the options
    foreach ($option in $Options)
    {
        Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
        $temp = Get-Variable "button$index" -ValueOnly
        $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $temp.UseVisualStyleBackColor = $True
        $temp.Text = $option
        $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
        $temp.Add_Click({ 
                $script:result = $this.Text; 
                $form.Close() 
            })
        $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
        $form.Controls.Add($temp)
        $index++
    }
    $shownString = '$this.Activate();'
    if ($DefaultChoice -ne -1)
    {
        $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
    }
    $shownSB = [ScriptBlock]::Create($shownString)
    $form.Add_Shown($shownSB)
    [void]$form.ShowDialog()
    return $result
}


# @FUNCTION@ ======================================================================================================================
# Name...........: CPMConnectionTest
# Description....: Performs multiple Casos calls against a vault
# Parameters.....: UserName, Password, VaultIP
# Return Values..: stdout txt file
# =================================================================================================================================
Function CPMConnectionTest(){

#Static
$VaultOperationFolder = "$PSScriptRoot\VaultOperationsTester"
$stdoutFile = "$VaultOperationFolder\Log\stdout.log"
$LOG_FILE_PATH_CasosArchive = "$VaultOperationFolder\Log\old"
$ZipToupload = "$VaultOperationFolder\_CPMConnectionTestLog"

        #If script ran for the first time, we perform this check and mark it down, afterwards we will skip this, and it can be ran from -Troubleshooting or with A Switch.
        $parameters = Try{Import-CliXML -Path $CONFIG_PARAMETERS_FILE}catch{Write-LogMessage -type Info -MSG "$($_.exception.message)" -Early}
    
        #If $parameters is empty, the initial script was never run or errored out, thus we skip straight to the test without the introduction.
        if($parameters){
            if (-not($parameters.contains("FirstCPMConnectionTest"))){ #if doesn't contain the value, then we delete existing file and create new 
            Remove-Item -Path $CONFIG_PARAMETERS_FILE
            $parameters += @{FirstCPMConnectionTest = $True}
            $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII -Force
            Write-LogMessage -type Info -MSG "** Since Vault Connectivity test passed, let's also run CPM Connection Install Test **"
            Write-LogMessage -type Info -MSG "** You will need to provide your Privilege Cloud Install Username and Password. **"
            #Ask if User wants to perform the test, subsequent runs won't show this question, you can only trigger this from Troubleshooting or -Switch.
            $decisionCPM = Get-Choice -Title "Run CPM Install Connection test?" -Options "Yes (Recommended)", "No" -DefaultChoice 1
                if ($decisionCPM -eq "No")
                {
                    Write-LogMessage -type Warning -MSG "OK, if you change your mind, you can always rerun the script with -CPMConnectionTest flag (or -Troubleshooting and selecting from menu)."
                    Pause
                    Exit
                }
            }
            ElseIf($CPMConnectionTest){
                #RunTheCheck
            }
            Else{
                #Since it's not the first script run, we skip this function.
                Break
            }
        }
 
 #Prereqs   
 if(!(Test-Path -Path "$VaultOperationFolder\VaultOperationsTester.exe")){
     Write-LogMessage -Type Error -Msg "Required folder doesn't exist: `"$VaultOperationFolder`". Make sure you get the latest version and extract it correctly from zip. Rerun the script with -CPMConnectionTest flag."
     Pause
     Return
 }
 if((Get-WmiObject -Class win32_product | where {$_.Name -like "Microsoft Visual C++ 2013 x86*"}) -eq $null){
    $CpmRedis = "$VaultOperationFolder\vcredist_x86.exe"
    Write-LogMessage -type Info -MSG "Installing Redis++ x86 from $CpmRedis..." -Early
    Start-Process -FilePath $CpmRedis -ArgumentList "/install /passive /norestart" -Wait
 }
        
        
        #Cleanup log file if it gets too big
        if (Test-Path $LOG_FILE_PATH_CasosArchive)
        {
            if (Get-ChildItem $LOG_FILE_PATH_CasosArchive | measure -Property length -Sum | where { $_.sum -gt 5MB })
            {
                Write-LogMessage -type Info -MSG "Archive log folder is getting too big, deleting it." -Early
                Write-LogMessage -type Info -MSG "Deleting $LOG_FILE_PATH_CasosArchive" -Early
                Remove-Item $LOG_FILE_PATH_CasosArchive -Recurse -Force
            }
        }
        
        #create file
        New-Item -Path $stdoutFile -Force | Out-Null
        Write-LogMessage -type Info -MSG "Begin CPM Connection Install Test"
        #Check if we can pull the Vault IP from the .ini file, otherwise prompt for it.
        if($parameters.VaultIP -eq $null){
            $VaultIP = Read-Host "Please enter your Vault Address"
        }
        Else{
            $VaultIP = $parameters.VaultIP
        }
        #Get Credentials
        Write-LogMessage -type Info -MSG "Enter Privilege Cloud Install User Credentials"
        $creds = Get-Credential -Message "Enter Privilege Cloud Install User Credentials"
        #Check pw doesn't contain illegal char, otherwise installation will fail
        [string]$illegalchars = '\/<>{}''&"$*@`|'
        $pwerror = $null
        if($($creds.GetNetworkCredential().Password).StartsWith('#')){
            Write-Host "illegal char detected # in first position" -ForegroundColor Red
            $pwerrorfirstchar = $true
        }
        foreach($char in $illegalchars.ToCharArray()){
            if ($($creds.GetNetworkCredential().Password).ToCharArray() -contains $char){
                Write-Host "illegal char detected $char" -ForegroundColor Red
                $pwerror = $true
            }
        }
        if($pwerrorfirstchar){
            Write-LogMessage -type Error -MSG "Password cannot start with a # as it will comment the rest of the line in powershell"
        }
        if($pwerror){
            Write-LogMessage -type Error -MSG "While the password can be set with high complexity in the vault post install, we require a simpler password just for the installation itself, make sure to not use the following chars: $illegalchars"
        }
        if($pwerror -or $pwerrorfirstchar){
            Write-LogMessage -type Error -MSG "Rerun the script with -CPMConnectionTest flag."
            Return
        }
    
        Write-LogMessage -type Success -MSG "Begin checking connection elements, should take 10-40 sec."
        $cleanupFromPreviousRuns = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($creds.UserName) $($creds.GetNetworkCredential().Password) $VaultIP CleanUp" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        $process = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($creds.UserName) $($creds.GetNetworkCredential().Password) $VaultIP" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        $creds = $null
        $stdout = (gc $stdoutFile)
            if($process.ExitCode -ne 0){
                #Compress the logs for easy support case upload
                Compress-Archive -Path "$VaultOperationFolder\Log" -CompressionLevel NoCompression -Force -DestinationPath $ZipToupload
                If($stdout -match "ITATS203E Password has expired"){
                    Write-LogMessage -type Error -MSG "You must first reset your initial password in the PVWA Portal, then you can rerun this test again by simply invoking the script with -CPMConnectionTest flag or -Troubleshooting flag and choose 'Run CPM Install Connection Test' option."
                    Pause
                    Break
                }
                Write-LogMessage -type Warning -MSG "Failed to simulate a healthy CPM install:"
                Write-Host "-----------------------------------------"
                $stdout | Select-String -Pattern 'Extra details' -NotMatch | Write-Host -ForegroundColor DarkGray
                Write-LogMessage -type Error -MSG "$($stdout | Select-String -Pattern 'Extra details')"
                
                Write-Host "-----------------------------------------"
                Write-LogMessage -type Warning -MSG "1) More detailed log can be found here: $VaultOperationFolder\Log\Casos.Error.log"
                Write-LogMessage -type Warning -MSG "2) Logs folder was zipped (Use for Support Case): `"$ZipToupload.zip`""
                [int]$lasthint = 4
                If($stdout -match "ITACM040S"){
                    [int]$lasthint = $lasthint+1
                    Write-LogMessage -type Warning -MSG "3) Hint: Communication over 1858/TCP is required to utilize sticky session and maintain the same source IP for the duration of the session."
                    Write-LogMessage -type Warning -MSG "4) In case of PA FW or similar configuration check out this page: "
                    Write-LogMessage -type Warning -MSG "   https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/Priv-Cloud-Firewall-setup.htm"
                }
                Else{
                    Write-LogMessage -type Warning -MSG "3) Hint: Typically this means there is a problem with Username/Password or FW configuration."
                }
                Write-LogMessage -type Warning -MSG "$lasthint) Rerun the script with -CPMConnectionTest flag."
            }
            Else{
                $stdout | Write-Host -ForegroundColor DarkGray
                Write-LogMessage -type Success -MSG "Connection is OK!"
            }
}



# @FUNCTION@ ======================================================================================================================
# Name...........: Set-ScriptParameters
# Description....: Stores variable for all user input fields
# Parameters.....: VaultIP, TunnelIP, PortalURL
# Return Values..: True/False
# =================================================================================================================================
Function Set-ScriptParameters()
{
[CmdletBinding(DefaultParameterSetName="Regular")]
param
(
	# Get the Portal URL
	[Parameter(ParameterSetName='Regular',Mandatory=$true, HelpMessage="Example: https://<customerDomain>.privilegecloud.cyberark.com")]
	[AllowEmptyString()]
	[Alias("PortalURL")]
	[ValidateScript({
		If(![string]::IsNullOrEmpty($_)) {
			($_ -like "*.privilegecloud.cyberark.com*") -or ($_ -like "*.cyberark.cloud*")
		}
		Else { $true }
	})]
	[String]${Please enter your provided portal URL Address (Or leave empty)},
	[Parameter(ParameterSetName='Regular',Mandatory=$true)]
	[AllowEmptyString()]
	[Alias("CustomerId")]
	[String]${Please enter your CustomerId (Or leave empty)},
	# Config File
	[Parameter(ParameterSetName='File',Mandatory=$true)]
	[ValidateScript({Test-Path $_})]
	[String]$ConfigFile
    
 )
	 If([string]::IsNullOrEmpty($ConfigFile))
	 {
        # ------ Copy parameter values entered ------
        $script:PortalURL = ${Please enter your provided portal URL Address (Or leave empty)}
        $script:CustomerId = ${Please enter your CustomerId (Or leave empty)}
        # grab the subdomain, depending how the user entered the url (hostname only or URL).
        if($script:portalURL -match "https://"){
            $script:portalURL = ([System.Uri]$script:PortalURL).host
            $script:portalSubDomainURL = $portalURL.Split(".")[0]
        }
        Else{
            $script:portalSubDomainURL = $PortalURL.Split(".")[0]
        }

        # Check if standard or shared services implementation.
        if($PortalURL -like "*.privilegecloud.cyberark.com*"){
            # Standard
            $script:VaultIP = "vault-$portalSubDomainURL.privilegecloud.cyberark.com"
            $script:TunnelIP = "connector-$portalSubDomainURL.privilegecloud.cyberark.com"
        }Elseif($PortalURL -like "*.privilegecloud.cyberark.cloud*"){
            # ispss
            $script:VaultIP = "vault-$portalSubDomainURL.privilegecloud.cyberark.cloud"
            $script:TunnelIP = "connector-$portalSubDomainURL.privilegecloud.cyberark.cloud"
        }Elseif($portalSubDomainURL -eq $null){
            # user didn't enter anything, do nothing in this case, so it skips the connection test.
        }		
			
		# Create the Config file for next use
		$parameters = @{
			PortalURL = $PortalURL.Trim()
			VaultIP = $VaultIP.trim()
			TunnelIP = $TunnelIP.trim()
            CustomerId = $CustomerId.trim()
		}
		$parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII
		# deal with ispss
        if($PortalURL -like "*.privilegecloud.cyberark.com*"){$script:g_ConsoleIP = $g_ConsoleIPstd}else{$script:g_ConsoleIP = $g_ConsoleIPispss}
	 }
	 else{
		$parameters = Import-CliXML -Path $CONFIG_PARAMETERS_FILE
		$script:VaultIP = $parameters.VaultIP
		$script:TunnelIP = $parameters.TunnelIP
		$script:PortalURL = $parameters.PortalURL
        $script:CustomerId = $parameters.CustomerId
		# deal with ispss
        if($PortalURL -like "*.privilegecloud.cyberark.com*"){$script:g_ConsoleIP = $g_ConsoleIPstd}else{$script:g_ConsoleIP = $g_ConsoleIPispss}
	 }
 }

Function AddLineToTable($action, $resultObject)
{

	$addLine = $false

    if ($resultObject.result -and $resultObject.errorMsg -ne "")
	{
        $mark = '[V]'
        $resultStr = "Warning"
        $addLine = $true
    }

    elseif (!$resultObject.result)
    {
        $mark = '[X]'
        $resultStr = "Failure"
        $addLine = $true
    }

    if ($addLine)
    {
        $objAverage = New-Object System.Object
        #$objAverage | Add-Member -type NoteProperty -name '   ' -value $mark
        $objAverage | Add-Member -type NoteProperty -name Result -value $resultStr
        $objAverage | Add-Member -type NoteProperty -name Check -value $action
        $objAverage | Add-Member -type NoteProperty -Name Expected -Value $resultObject.expected
        $objAverage | Add-Member -type NoteProperty -Name Actual -Value $resultObject.actual
        $objAverage | Add-Member -type NoteProperty -Name Description -Value $resultObject.errorMsg
        
        $global:table += $objAverage
    }
}

Function AddLineToReport($action, $resultObject)
{

    $status = 'FAILED'
    $line = ""
	$errMessage = $resultObject.errorMsg

    $actionPad = $action

    if($resultObject.errorMsg -ne "")
    {
        $errMessage= "- $errMessage"
    }

	if($resultObject.result)
	{
        $mark = '[V]'
        $status = 'PASS'

        $line = "$mark $actionPad $errMessage"
        if($errMessage-ne "")
        {
            Write-LogMessage -Type Warning -Msg $line
        }
        else
        { 
            Write-LogMessage -Type Success -Msg $line 
        }
    }
    else
    {
        $mark = '[X]'
        $line = "$mark $actionPad $errMessage"
        Write-LogMessage -Type Error -Msg $line
    }
}
 
Function CheckPrerequisites()
{

	Try
	{
        $cnt = ($arrCheckPrerequisites.Values[0]+$arrCheckPrerequisites.Values[1]+$arrCheckPrerequisites.Values[2]+$arrCheckPrerequisites.Values[3]).Count
		Write-LogMessage -Type Info -SubHeader -Msg "Starting checking $cnt prerequisites..."
		
        $global:table = @()
        $errorCnt = 0
        $warnCnt = 0
        $table = ""

		ForEach ($methods in $arrCheckPrerequisites)
        {
            Write-LogMessage -Type Warning -Msg "< $($methods.Keys) Related Checks >"
            ForEach($method in $($methods.Values))
            {
                Try
                { 
                    Write-Progress -Activity "Checking $method..."
                    $resultObject = &$method  

                    if($null -eq $resultObject -or !$resultObject.result)
                    {
                        $errorCnt++
                    }

                    Write-Progress -Activity "$method completed" -Completed      
                }
                Catch
                {
                    $resultObject.errorMsg = $_.Exception.Message
                    $errorCnt++
                }

			    if($resultObject.errorMsg -ne $g_SKIP)
			    {
			    	AddLineToReport $method $resultObject
			    }
			    else
			    {
			    	# remove the skip description
			    	$resultObject.errorMsg = ""
			    }
			    
                AddLineToTable $method $resultObject
            }
        }
        
        Write-LogMessage -Type Info -Msg " " -Footer
		
        $errorStr = "";
        $warnStr = "";


        if($global:table.Count -gt 0)
        {       
            if($errorCnt -eq 1)
			{
				$errorStr = "failure"
			}
			else
			{
				$errorStr = "failures"
			}

			$warnCnt = $global:table.Count - $errorCnt

			if($warnCnt -eq 1)
			{
				$warnStr = "warning"
			}
			else
			{
				$warnStr = "warnings"
			}


			Write-LogMessage -Type Info -Msg "Checking Prerequisites completed with $errorCnt $errorStr and $warnCnt $warnStr"

            Write-LogMessage -Type Info -Msg "$SEPARATE_LINE"
            $global:table | Format-Table -Wrap
            #$global:table | Format-Table -Wrap -AutoSize

            Write-LogMessage -Type LogOnly -Msg $($global:table | Out-String)
        }
        else
        {
            Write-LogMessage -Type Success -Msg "Checking Prerequisites completed successfully"
        }

        Write-LogMessage -Type Info -Msg " " -Footer
	}
	Catch
	{
        Throw $(New-Object System.Exception ("CheckPrerequisites: Failed to run CheckPrerequisites",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-VersionUpdate
# Description....: Tests the latest version and downloads the latest script if found
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Test-VersionUpdate()
{
	# Define the URLs to be used
	$pCloudServicesURL = "https://raw.githubusercontent.com/pCloudServices/ps/master"
	$pCloudLatest = "$pCloudServicesURL/Latest.txt"
	$pCloudScript = "$pCloudServicesURL/$g_ScriptName"
	
	#Write-LogMessage -Type Info -Msg "Current version is: $versionNumber"
	Write-LogMessage -Type Info -Msg "Checking for new version" -Early
	$checkVersion = ""
	$webVersion = New-Object System.Net.WebClient

#Ignore certificate error
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
		$certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
			Add-Type $certCallback
	}
	[ServerCertificateValidationCallback]::Ignore()
    #ERROR: The request was aborted: Could not create SSL/TLS secure channel.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    
	Try
	{
		$resWebCall = (Invoke-WebRequest -UseBasicParsing -Uri $pCloudLatest -ErrorAction Stop)
		If($resWebCall.StatusCode -eq "200")
		{
			[int]$checkVersion = $resWebCall.Content.trim()
		}
	}
	Catch
	{
		Write-LogMessage -Type Info -Msg "Test-VersionUpdate: Couldn't check for latest version, probably DNS/FW Issue: $(Collect-ExceptionMessage $_.Exception.Message)" -Early
	}

	If ($checkVersion -gt $versionNumber)
	{
		Write-LogMessage -Type Info -Msg "Found new version: $checkVersion Updating..."
		Try
		{
			Invoke-WebRequest -UseBasicParsing -Uri $pCloudScript -ErrorAction Stop -OutFile "$PSCommandPath.NEW"
		}
		Catch
		{
			Throw $(New-Object System.Exception ("Test-VersionUpdate: Couldn't download latest version",$_.Exception))
		}

		If (Test-Path -Path "$PSCommandPath.NEW")
		{
			Rename-Item -path $PSCommandPath -NewName "$PSCommandPath.OLD"
			Rename-Item -Path "$PSCommandPath.NEW" -NewName $g_ScriptName
			Remove-Item -Path "$PSCommandPath.OLD"
            $scriptPathAndArgs = "& `"$g_ScriptName`" -POC:$POC -OutOfDomain:$OutOfDomain -Troubleshooting:$Troubleshooting"
			Write-LogMessage -Type Info -Msg "Finished Updating, please close window (Regular or ISE) and relaunch script."
			Pause
			Exit
		}
		Else
		{
			Write-LogMessage -Type Error -Msg "Can't find the new script at location '$PSScriptRoot'."
		}
	}
	Else
	{
		Write-LogMessage -Type Info -Msg "Current version is the latest!" -Early
	}
}

#endregion

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
	param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$Early,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose", "Success", "LogOnly")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
			Write-Host "------------------------------------" -ForegroundColor Magenta
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			{($_ -eq "Info") -or ($_ -eq "LogOnly")} 
			{ 
				If($_ -eq "Info")
				{
					Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "magenta" } Elseif($Early){"DarkGray"} Else { "White" })
				}
				$msgToWrite += "[INFO]`t$Msg"
			}
			"Success" { 
				Write-Host $MSG.ToString() -ForegroundColor Green
				$msgToWrite += "[SUCCESS]`t$Msg"
            }
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite += "[WARNING]`t$Msg"
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose -Msg $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else { $writeToFile = $False }
			}
		}

		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message"),$_.Exception)
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Collect-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Collect-ExceptionMessage
{
<# 
.SYNOPSIS 
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
		  $e = $e.InnerException
		  $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogHeader
# Description....: Creates the log header
# Parameters.....: None
# Return Values..: The HEader string 
# =================================================================================================================================
Function Get-LogHeader
{
    return @"
	
###########################################################################################
#
#                       Privilege Cloud Pre-requisites Check PowerShell Script
#
# Version : $versionNumber
# CyberArk Software Ltd.
###########################################################################################
"@
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogoHeader
# Description....: Creates the logo header
# Parameters.....: None
# Return Values..: The Header image
# =================================================================================================================================
Function Get-LogoHeader{
$t = @"
  ____      _                _         _    
 / ___|   _| |__   ___ _ __ / \   _ __| | __
| |  | | | | '_ \ / _ \ '__/ _ \ | '__| |/ /
| |__| |_| | |_) |  __/ | / ___ \| |  |   < 
 \____\__, |_.__/ \___|_|/_/   \_\_|  |_|\_\
      |___/ 

"@

for ($i=0;$i -lt $t.length;$i++) {
if ($i%2) {
 $c = "yellow"
}
elseif ($i%5) {
 $c = "magenta"
}
elseif ($i%7) {
 $c = "red"
}
else {
   $c = "yellow"
}
write-host $t[$i] -NoNewline -ForegroundColor $c
}
}

#endregion

#region Main Script
###########################################################################################
# Main start
###########################################################################################
if($psISE -ne $null){
    Write-Host "You're not suppose to run this from ISE."
    Pause
    Exit
}

$Host.UI.RawUI.WindowTitle = "Privilege Cloud Prerequisites Check"

#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH)
{
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 5000KB })
    {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it."
        Remove-Item $LOG_FILE_PATH -Force
    }

}

Write-LogMessage -Type Info -Msg $(Get-LogHeader) -Header
Get-LogoHeader
Write-LogMessage -Type Verbose -Msg "Verify user is a local Admin"
$adminUser = IsUserAdmin 
# Run only if the User is a local admin on the machine
If ($adminUser -eq $False)
{
	Write-LogMessage -Type Error -Msg "You must logged on as a local administrator in order to run this script"
    pause
	return
}
    #troubleshooting section
if ($Troubleshooting){Troubleshooting}
    #Run CPM Install Test
if ($CPMConnectionTest){CPMConnectionTest}
else
{
	try {
        # Check the latest version
		if(! $SkipVersionCheck){
            Write-LogMessage -Type Info -Msg "Checking for latest version" -Early
            Test-VersionUpdate 
        }
        Else{ Write-LogMessage -Type Info -Msg "Skipped version check" -Early }
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to check for latest version - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
    try {
		if(Test-Path $CONFIG_PARAMETERS_FILE)
		{
			Write-LogMessage -type Info -MSG "Getting parameters from config file '$CONFIG_PARAMETERS_FILE'" -Early
			Set-ScriptParameters -ConfigFile $CONFIG_PARAMETERS_FILE
            #CheckConnectionToVault
		}
		else
		{
            #In case user placed ConnectionDetails.txt file in the same folder we can grab all the values from it.
            Write-LogMessage -type Info -MSG "Checking if ConnectionDetails.txt file exist so we can fetch values from there instead of manually typing them." -Early
            $ConnectionDetailsFile = "$PSScriptRoot\*ConnectionDetails.txt"    
            if (Test-Path $ConnectionDetailsFile){
            $PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:")).Host
            #Deal with TM format
            if($PortalURL -eq $null)
                {
                $PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:").Trim()).OriginalString
                }
            if($PortalURL -match "https://")
	            {
		        $PortalURL = ([System.Uri]$PortalURL).Host
	            }
            $CustomerId = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "CustomerId:").ToString().ToLower().trim("customerid:").Trim()
            $VaultIP = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "VaultIp:").ToString().ToLower().trim("vaultip:").Trim()
            $TunnelIP = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "ConnectorServerIp:").ToString().ToLower().trim("connectorserverip:").Trim()

            $parameters = @{
			    PortalURL = $PortalURL
			    VaultIP = $VaultIP
			    TunnelIP = $TunnelIP
                CustomerId = $CustomerId
		    }
		    $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII
		    }
            ElseIf($PortalURL -match "https://")
	            {
		        $PortalURL = ([System.Uri]$PortalURL).Host
	            }
            Else
            {
			Write-LogMessage -type Info -MSG "Prompting user for input" -Early
			Set-ScriptParameters #Prompt for user input
            }
		}
    } catch {
        Write-LogMessage -type Error -MSG "Failed to Prompt user for input - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
    }    
	try {
        # Retrieve public IP and save it locally
        if(! $SkipIPCheck){
		    Write-LogMessage -Type Verbose -Msg $(GetPublicIP)
        }
        Else{ Write-LogMessage -Type Info -Msg "Skipped Online IP check" -Early }
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to retrieve public IP - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	try {
        # Main Pre-requisites check
		CheckPrerequisites
        # If VaultConnectivity passed, run CPM Test.
        if($VaultConnectivityOK -eq $true){CPMConnectionTest}
	} catch	{
		Write-LogMessage -Type Error -Msg "Checking prerequisites failed. Error(s): $(Collect-ExceptionMessage $_.Exception)"
	}
}
Write-LogMessage -Type Info -Msg "Script Ended" -Footer	
###########################################################################################
# Main end
###########################################################################################	
#endregion
# SIG # Begin signature block
# MIIgTgYJKoZIhvcNAQcCoIIgPzCCIDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDl8N/x6iY5H3L4
# /FbzZJ1APYJ9O5h73kufocL3PwgPKqCCDl8wggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB28wggVXoAMCAQICDHBNxPwWOpXgXVV8
# DDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjIwMjE1MTMzODM1WhcNMjUwMjE1MTMzODM1WjCB
# 1DEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxEDAOBgNVBAgT
# B0NlbnRyYWwxFDASBgNVBAcTC1BldGFoIFRpa3ZhMRMwEQYDVQQJEwo5IEhhcHNh
# Z290MR8wHQYDVQQKExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZD
# eWJlckFyayBTb2Z0d2FyZSBMdGQuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA8rPX6yAVM64+/qMQEttWp7FdAvq9UfgxBrW+R0NtuXhKnjV05zmIL6zi
# AS0TlNrQqu5ypmuagOWzYKDtIcWEDm6AuSK+QeZprW69c0XYRdIf8X/xNUawXLGe
# 5LG6ngs2uHGtch9lt2GLMRWILnKviS6l6F06HOAow+aIDcNGOukddypveFrqMEbP
# 7YKMekkB6c2/whdHzDQiW6V0K82Xp9XUexrbdnFpKWXLfQwkzjcG1xmSiHQUpkSH
# 4w2AzBzcs+Nidoon5FEIFXGS2b1CcCA8+Po5Dg7//vn2thirXtOqaC+fjP1pUG7m
# vrZQMg3lTHQA/LTL78R3UzzNb4I9dc8yualcYK155hRU3vZJ3/UtktAvDPC/ewoW
# thebG77NuKU8YI6l2lMg7jMFZ1//brICD0RGqhmPMK9MrB3elSuMLaO566Ihdrlp
# zmj4BRDCfPuH0QfwkrejsikGEMo0lErfHSjL3NaiE0PPoC4NW7nc6Wh4Va4e3VFF
# Z9zdnoTsCKJqk4s13MxBbjdLIkCcfknMSxAloOF9h6IhzWOylSROAy/TZfGL5kzQ
# qxzcIhdXLWHHWdbz4DD3qxYc6g1G3ZwgFPWf7VbKQU3FsAxgiJvmKPVeOfIN4iYT
# V4toilRR8KX/IaA1NMrN9EiA//ZhN3HONS/s6AxjjHJTR29GOQkCAwEAAaOCAbYw
# ggGyMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYBBQUH
# MAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2NjcjQ1
# ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmds
# b2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAETjBM
# MEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1UdHwRA
# MD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAW
# gBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQU0Vg7IAYAK18fI9dI1YKi
# WA0D1bEwDQYJKoZIhvcNAQELBQADggIBAFOdA15mFwRIM54PIL/BDZq9RU9IO+YO
# lAoAYTJHbiTY9ZqvA1isS6EtdYKJgdP/MyZoW7RZmcY5IDXvXFj70TWWvfdqW/Qc
# MMHtSqhiRb4L92LtR4lS+hWM2fptECpl9BKH28LBZemdKS0jryBEqyAmuEoFJNDk
# wxzQVKPksvapvmSYwPiBCtzPyHTRo5HnLBXpK/LUBJu8epAgKz6LoJjnrTIF4U8R
# owrtUC0I6f4uj+sKYE0iV3/TzwsTJsp7MQShoILPr1/75fQjU/7Pl2fbM++uAFBC
# sHQHYvar9KLslFPX4g+cDdtOHz5vId8QYZnhCduVgzUGvELmXXR1FYV7oJNnh3eY
# Xc5gm7vSNKlZB8l7Ls6h8icBV2zQbojDiH0JOD//ph62qvnMp8ev9mvhvLXRCIxc
# aU7CYI0gNVvg9LPi5j1/tswqBc9XAfHUG9ZYVxYCgvynEmnJ5TuEh6GesGRPbNIL
# l418MFn4EPQUqxB51SMihIcyqu6+3qOlco8Dsy1y0gC0Hcx+unDZPsN8k+rhueN2
# HXrPkAJ2bsEJd7adPy423FKbA7bRCOc6dWOFH1OGANfEG0Rjw9RfcsI84OkKpQ7R
# XldpKIcWuaYMlfYzsl+P8dJru+KgA8Vh7GTVb5USzFGeMyOMtyr1/L2bIyRVSiLL
# 8goMl4DTDOWeMYIRRTCCEUECAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjACDHBNxPwWOpXgXVV8DDANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB5
# G1PQrHs+DsLmaCLVY/tPBuP/xU7DFTDJCDpwHtwj5jANBgkqhkiG9w0BAQEFAASC
# AgCAWHmJe+SWUcmQgNJtzcblJ3X664bBNM66LgZhtNUeVQyEaUEkUsxwm2keSn4Y
# saH3KDlvt9gAr5zpeLNZSFkuDdjNBtSIUbyGCsbTURdTKge5NtVgv0ef2LeTh2pK
# uDvVSunjZLAm9EVmUs/uFmpyJw7aBsqpjwhkueEIEjFcCWBPuuqGgetaDvOiPsPG
# 5ZsOkUhWuvXl2+guCXdmIyjkuGdnyNd7jV/jPPf1yW0MtAHNi+UAgVsTKzRupgx+
# rTXSD2Mb+5jrYTF31IgW2taUpI0FSV71qCNzvUOQXY11X6dgNS2vKP4V39+j/IVH
# ZDHpuw/QXDRjis6xe9pG01g80unPmxkxBwM9n6E4kuBxoLJaaEALroSCwN1TjZvw
# T5a5naTLfQH7g73E+ccYz9t13i7GBqa0a9JUUyQ+X2DYnHT7snTHCG+FHfBGcHSx
# ARkFNgApj+REcPg1Aou0h06WrXGOqVJLX0Mqv1gRBM0xW60VKmX4c5YgsDu76cOp
# ZXPfYb+wOuVzCPYuBph8/x0KPvbdnF4L1kz1Ff8lAsICUdzi3D08FtjUp1H01Ym0
# giQFymiWYC96cKqj6y8ZUzI8l5PuJaKi8U7M642zyqGsj75InCgPIEDz1zYNGyah
# I90L59CjAdpq0tc+GWUYeRJd2gw9/wehiTmaZtasX20pGqGCDiwwgg4oBgorBgEE
# AYI3AwMBMYIOGDCCDhQGCSqGSIb3DQEHAqCCDgUwgg4BAgEDMQ0wCwYJYIZIAWUD
# BAIBMIH/BgsqhkiG9w0BCRABBKCB7wSB7DCB6QIBAQYLYIZIAYb4RQEHFwMwITAJ
# BgUrDgMCGgUABBTnsvCfZGr4cxWYEnDLHPNcm6RJ/wIVAJ5QAbgDNmRa8r+p2KHS
# gUYLnZjxGA8yMDIyMTExNTE0MjcyNFowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMC
# VVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1h
# bnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGlt
# ZVN0YW1waW5nIFNpZ25lciAtIEczoIIKizCCBTgwggQgoAMCAQICEHsFsdRJaFFE
# 98mJ0pwZnRIwDQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29y
# azE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9y
# aXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJvb3Qg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEyMDAwMDAwWhcNMzEwMTEx
# MjM1OTU5WjB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9y
# YXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMT
# H1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61XzsAGtPHGsMo8Fa4aaJwAy
# l2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/Xm1AONSRBudBfHkcy8ut
# G7/YlZHz8O5s+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9ITh
# xNF8ccYGKbQ/5IMNJsN7CD5N+Qq3M0n/yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+
# vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1inisGTKPI8EyQRtZDqk+
# scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3AgMBAAGjggF3MIIBczAO
# BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsG
# C2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20v
# Y3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMC4GCCsG
# AQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Muc3ltY2QuY29tMDYGA1Ud
# HwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91bml2ZXJzYWwtcm9vdC5j
# cmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMT
# EFRpbWVTdGFtcC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MB8GA1UdIwQYMBaAFLZ3+mlIR59TEtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUA
# A4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociBiPenjxXmQCmt5l30otlW
# ZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7zJAv1gpsTjPs1rSTyEyQ
# Y0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72
# a433Snq+8839A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnj
# OgC/zoqUywHbnsc4uw9Sq9HjlANgCk2g/idtFDL8P5dA4b+ZidvkORS92uTTw+or
# WrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIBAgIQe9Tlr7rMBz+hASME
# IkFNEjANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3lt
# YW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdv
# cmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcN
# MTcxMjIzMDAwMDAwWhcNMjkwMzIyMjM1OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAb
# BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBU
# cnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1w
# aW5nIFNpZ25lciAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# rw6Kqvjcv2l7VBdxRwm9jTyB+HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/
# J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uP
# CB1ySFdlTa8CPED39N0yOJM/5Sym81kjy4DeE035EMmqChhsVWFX0fECLMS1q/Js
# I9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/SrcidmXs7DbylpWB
# Jiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTO
# PAPstwDyOiLFtG/l77CKmwIDAQABo4IBxzCCAcMwDAYDVR0TAQH/BAIwADBmBgNV
# HSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5z
# eW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20v
# cnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1jcmwud3Muc3ltYW50ZWMu
# Y29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4G
# A1UdDwEB/wQEAwIHgDB3BggrBgEFBQcBAQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6
# Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL3Rz
# LWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jZXIwKAYDVR0RBCEw
# H6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTYwHQYDVR0OBBYEFKUTAamf
# hcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQYMBaAFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MA0GCSqGSIb3DQEBCwUAA4IBAQBGnq/wuKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5
# Rk7nfmUGWIu8V4qSDQjYELo2JPoKe/s702K/SpQV5oLbilRt/yj+Z89xP+YzCdmi
# WRD0Hkr+Zcze1GvjUil1AEorpczLm+ipTfe0F1mSQcO3P4bm9sB/RDxGXBda46Q7
# 1Wkm1SF94YBnfmKst04uFZrlnCOvWxHqcalB+Q15OKmhDc+0sdo+mnrHIsV0zd9H
# CYbE/JElshuW6YUI6N3qdGBuYKVWeg3IRFjc5vlIFJ7lv94AvXexmBRyFCTfxxEs
# HwA/w0sUxmcczB4Go5BfXFSLPuMzW4IPxbeGAk5xn+lmRT92MYICWjCCAlYCAQEw
# gYswdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u
# MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1h
# bnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhB71OWvuswHP6EBIwQiQU0SMAsG
# CWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTIyMTExNTE0MjcyNFowLwYJKoZIhvcNAQkEMSIEIFMBJsvCq/Ep
# Cza0Ibf9lzArMQdSme2EbgWuOykDpLprMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIE
# IMR0znYAfQI5Tg2l5N58FMaA+eKCATz+9lPvXbcf32H4MAsGCSqGSIb3DQEBAQSC
# AQBEmM1i35ScVt3zXogqxVn4YnjQvUzZA+ed96LZAyse/tTfrXglBvybrEo3VAI+
# aiEW/HKOUmAmuXIjxqSHrDyhBHbFroZg7f6guWslFuCLiENM05rfseqG7iPcJ57U
# nqCTtS9kLT7i5EFMAbIZaxLc85x7Iuvq4AyOoE6GXQT5oTGE0TwXQCuOvIB5JWrs
# sNZKZCpsMjNRw/auAAG4YWNOeM0owgGZbz/jMeGdzo1lRfjllf93ymYznY8/Vd59
# dpkrgh1rC5Z4S/LKA5ck01CTyr/NxK430JCgd5wISWBp3rXWdNOWW2KsLU0slw5W
# nZ/8yNfv5hWop9L38ONX7jOM
# SIG # End signature block
