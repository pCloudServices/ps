###########################################################################
#
# NAME: Privilege Cloud Prerequisites check
#
# AUTHOR:  Mike Brook
#
# COMMENT: 
# Script checks prerequisites for Privilege Cloud Connector machine
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="")]
 <#
  .DESCRIPTION
  Script checks prerequisites for Privilege Cloud Connector machine
  
  .PARAMETER OutOfDomain
 
  .EXAMPLE1 
  PS C:\> .\PSMCheckPrerequisites.ps1
  
  .EXAMPLE2 - Run checks if machine is out of domain
  PS C:\> .\PSMCheckPrerequisites.ps1 -OutOfDomain

  .EXAMPLE2 - Troubleshoot certain components
  PS C:\> .\PSMCheckPrerequisites.ps1 -Troubleshooting
  
#>
param
(
	# Use this switch to Simulate with no change
	[Parameter(Mandatory=$false)][switch]$OutOfDomain,
	[switch]$Troubleshooting,
	[Parameter(Mandatory=$true,HelpMessage="Please enter your Vault IP Address (Leave empty if you don't have it)")]
	[AllowEmptyString()]
	[String]$VaultIP,
	[Parameter(Mandatory=$true,HelpMessage="Please enter your TunnelConnector IP Address (Leave empty if you don't have it)")]
	[AllowEmptyString()]
	[String]$TunnelIP,
	[Parameter(Mandatory=$true,HelpMessage="Please enter your provided portal URL Address, Example: https://<customerDomain>.privilegecloud.cyberark.com (Leave empty if you don't have it)")]
	[ValidateScript({$_ -like "https://*.privilegecloud.cyberark.com"})]
	[String]$PortalURL
)

# ------ SET Script Prerequisites ------
##############################################################

# Enter the list of checks to be performed.
$arrCheckPrerequisites = @(
"VaultConnectivity",
"TunnelConnectivity",
"CustomerPortalConnectivity",
"ConsoleNETConnectivity",
"ConsoleHTTPConnectivity",
"CRLConnectivity",
"OSVersion",
"Processors",
"Memory",
"SQLServerPermissions",
"UsersLoggedOn",
"KBs",
"IPV6",
"PSRemoting",
"CheckNoRDS",
"DomainUser",
"PendingRestart",
"NotAzureADJoinedOn2019",
"GPO"
)


## Enter the list of GPOs to check.
$arrGPO = @(
       [pscustomobject]@{Name='Require user authentication for remote connections by using Network Level Authentication';Expected='Disabled'}
	   [pscustomobject]@{Name='Select RDP transport protocols'; Expected='Disabled'}	
       [pscustomobject]@{Name='Use the specified Remote Desktop license servers'; Expected='Disabled'}   
	   [pscustomobject]@{Name='Set client connection encryption level'; Expected='Disabled'}
	   [pscustomobject]@{Name='Use Remote Desktop Easy Print printer driver first'; Expected='Disabled'}
   )

##############################################################

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
[int]$versionNumber = "11"

# ------ SET Files and Folders Paths ------
# Set Log file path
$global:LOG_DATE = $(get-date -format yyyyMMdd) + "-" + $(get-date -format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\PrivCloud-CheckPrerequisites-$LOG_DATE.log"

# ------ SET Global Parameters ------
$global:g_ConsoleIP = "console.privilegecloud.cyberark.com"
$global:g_ScriptName = "PSMCheckPrerequisites_pCloudEdit.ps1"

$global:table = ""
$SEPARATE_LINE = "------------------------------------------------------------------------" 
$g_SKIP = "SKIP"

#region Troubleshooting
Function BindAccount{
Function Connect-LDAPS(){
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$false)][string] $hostname = (Read-Host -Prompt "Enter Hostname (eg; cyberarkdemo.com)"),
        [parameter(Mandatory=$false)][int] $Port = (read-host -Prompt "Enter Port($("636"))"),
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

function Show-Menu
{
    Clear-Host
    Write-Host "================ Troubleshooting Guide ================"
    
    Write-Host "1: Press '1' to Test LDAPS Bind Account" -ForegroundColor Green
    Write-Host "Q: Press 'Q' to quit."
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


         
     }
     pause
 }
 until ($selection -eq 'q')
 exit
 }

Function GetListofDCsAndTestBindAccount()
{
$UserPrincipal = Get-UserPrincipal
if(($UserPrincipal.ContextType -eq "Domain") -and (!(Test-Path "$PSScriptRoot\DCInfo.txt"))){

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
Write-Host -ForegroundColor Cyan "Below DC Info will be printed once and stored in local file `"DCInfo.txt`"."
Write-Host -ForegroundColor Cyan "Delete the file if you want to perform this check again."
Test-LDAP |format-table| Tee-Object -file "$PSScriptRoot\DCInfo.txt"
}
}

#endregion

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
	try{
		Write-LogMessage -Type Verbose -Msg "Starting CheckNoRDS..."
		$errorMsg = ""
		$result = $True
		$actual = (Get-WindowsFeature Remote-Desktop-Services).InstallState -eq "Installed"
		If($actual -eq $True)
		{
			$result = $False
			$errorMsg = "RDS shouldn't be deployed before CyberArk is installed, remove RDS role and make sure there are no domain level GPO RDS settings applied (rsop.msc). Please note, after you remove RDS and restart you may need to use 'mstsc /admin' to connect back to the machine."
		}
		Write-LogMessage -Type Verbose -Msg "Finished CheckNoRDS"
	} catch {
		$errorMsg = "Could not check RDS installation. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $False;
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
<#
Why are we disabling it now?
Should we log that we are disabling this?
This will aply only after restart I think

		#Disable IPv6 on NIC
		Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

		#Disable IPv6 on Registry
		New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "0" -PropertyType DWORD -Force
#>
		
		$arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress
		$IPv6Status = ($arrInterfaces | where { $_.contains("::") }).Count -gt 0

		if($IPv6Status)
		{
			$actual = "Enabled"
			$result = $false
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
				$errorMsg = "Could not connect using PSRemoting to $($env:COMPUTERNAME)"
			}
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
				$pcHotFixes = Get-HotFix $hotFixes -EA ignore | select -Property HotFixID 
		
				#none of the KBs installed
				if($pcHotFixes -eq $null)
				{
					$errorMsg = "KBs not installed: $hotFixes"
					$actual = "Not Installed"
					$result = $false
				}

				else
				{	
					$HotfixesNotInstalled = $hotFixes | Where { $_ -notin $pcHotFixes }
		
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
    
		if ((gwmi win32_computersystem).partofdomain) 
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
			$UserPrincipal = Get-UserPrincipal

			if($UserPrincipal.ContextType -eq "Domain")
			{
				$actual = "Domain user"
				$result = $true 
			}
			else 
			{
				$actual = "Not Domain user"
				$result = $false
			}
		}

		Write-LogMessage -Type Verbose -Msg "Finished DomainUser"
	} catch {
		$errorMsg = "Could not verify if user is a Domain user. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "Domain User";
		actual = $actual;
		errorMsg = "";
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

		$regComponentBasedServicing = (dir 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' | where { $_.Name -contains "RebootPending" })
		$regWindowsUpdate = (dir 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' | where { $_.Name -contains "RebootRequired" })
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
			$actual = "More than one user is logged on"
			Write-LogMessage -Type Warning -Msg $actual
			$errorMsg = "Please see log for details"
			$result = $False
		}
		else
		{
			$actual = "Only one user is logged on"
			$result = $True
		}
	}catch{
		Write-LogMessage -Type Error -Msg "Cannot check if another user is logged on"
		$errorMsg = $g_SKIP
		$result = $false
	}
	
	Write-LogMessage -Type Verbose -Msg "Finished UsersLoggedOn"
	
    return [PsCustomObject]@{
        expected = "Only one user is logged on";
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

		if($arrGPO.Count -gt 0)
		{
			ForEach ($gpo in $arrGPO)
			{
				$errorMsg = ""
				$GPOValueResult = ReadGPOValue -gpoXML $xml -gpoName $gpo.Name 

				if ([string]::IsNullOrEmpty($GPOValueResult))
				{
					$actual = "Not Configured"
					$gpoResult = $true
				}
				else
				{
					$actual = $GPOValueResult

					$gpoResult = ($gpo.Expected -eq $GPOValueResult)
					
					if(-not $gpoResult )
					{
						$compatible = $false
						$errorMsg = "Expected:"+$gpo.Expected+" Actual:"+$actual
					}
				}
			
				$name = "GPO: "+$gpo.Name
				Write-LogMessage -Type Verbose -Msg ("{0}; Expected: {1}; Actual: {2}" -f $name, $gpo.Expected, $actual)
				$reportObj = @{expected = $gpo.Expected; actual = $actual; errorMsg = $errorMsg; result = $gpoResult;}
				#AddLineToReport $name $reportObj #TODO: Check this method
				AddLineToTable $name $reportObj
			}#loop end
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
# Description....: Tests Vault network connectivity on port 1858
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function VaultConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Runing VaultConnectivity"
	return Test-NetConnectivity -ComputerName $VaultIP -Port 1858
}

# @FUNCTION@ ======================================================================================================================
# Name...........: TunnelConnectivity
# Description....: Tests Tunnel network connectivity on port 5511
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function TunnelConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Running TunnelConnectivity"
    return Test-NetConnectivity -ComputerName $TunnelIP -Port 5511
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleNETConnectivity
# Description....: Tests Privilege Cloud network connectivity on port 443
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
# Name...........: ConsoleNETConnectivity
# Description....: Tests Privilege Cloud network connectivity on port 443
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
			#TODO: is it OK that we have here a constant customer ID? should we get he current customer ID?
			$connectorConfigURL = "https://$g_ConsoleIP/connectorConfig/v1?customerId=35741f0e-71fe-4c1a-97c8-28594bf1281d&configItem=environmentFQDN"
			$CustomerGenericGET = Invoke-RestMethod -Uri $connectorConfigURL -TimeoutSec 20 -ContentType 'application/json'
			If($null -ne $CustomerGenericGET)
			{
				$actual = $CustomerGenericGET.config.environmentFQDN.attributes.environmentFQDN.Length
				$result = ($actual -eq 39)
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
		expected = "39";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CRLConnectivity
# Description....: Tests CRL connectivity
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

		$cert1 = 0
		$cert2 = 0
		Try{
			$cert1 = Invoke-WebRequest -Uri http://crl3.digicert.com/CloudFlareIncECCCA2.crl -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing  | select -ExpandProperty StatusCode
			$cert2 = Invoke-WebRequest -Uri http://crl4.digicert.com/CloudFlareIncECCCA2.crl -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing | select -ExpandProperty StatusCode

			If(($cert1 -eq 200) -and ($cert2 -eq 200))
			{
				$actual = "200"
				$result = $true
			}
		} catch {
			if ($Error[0].ErrorDetails.Message -eq "404 - Not Found")
			{
				$errorMsg = "Can't find CRL file on target site, was it changed? Contact CyberArk"
			}
			else
			{
				Throw $(New-Object System.Exception ("CRLConnectivity: Can't resolve hostname (digicert.com), check DNS settings",$_.Exception))
			}
		}
			
		Write-LogMessage -Type Verbose -Msg "Finished CRLConnectivity"
	} catch {
		$errorMsg = "Could not verify CRL connectivity. Error: $(Collect-ExceptionMessage $_.Exception)"
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
# Description....: Tests Privilege Cloud Console network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CustomerPortalConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Running CustomerPortalConnectivity"
	if ($PortalURL -match "https://")
	{
		$PortalURL = ([System.Uri]$PortalURL).Host
	}
    return Test-NetConnectivity -ComputerName $PortalURL -Port 443
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Processors
# Description....: Tests minimum required CPU cores
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
# Description....: Tests minimum required Memory
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
		$Memory = [math]::Round(((Get-CimInstance CIM_PhysicalMemory).Capacity | Measure-Object -Sum).Sum / 1GB, 2)
		$MemoryAWS = [math]::Round((Get-CimInstance -ClassName CIM_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
		
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
# Description....: Tests required SQL Server permissions
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
			if($administrators -eq $null)
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
						$actual = $result = $True
					}
					else
					{
						Write-LogMessage -Type Verbose -Msg "No Local Administrators access for $sec group policy"
						$actual = $result = $False
						$errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
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
# Name...........: NotAzureADJoinedOn2019
# Description....: Checks if the server is joined to Azure Domain and on Win2019 (known bug)
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function NotAzureADJoinedOn2019
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		$actual = $False
		$result = $False
		$errorMsg = ""
		Write-LogMessage -Type Verbose -Msg "Starting NotAzureADJoinedOn2019..."
		$CheckIfMachineIsOnAzure = ((((dsregcmd /status) -match "AzureAdJoined" | Out-String).Split(":") | Select-Object -Skip 1) -match "YES")
		$Machine2019 = (Get-WmiObject Win32_OperatingSystem).caption -like '*2019*'

		if ($CheckIfMachineIsOnAzure -and $Machine2019){
			$errorMsg = "Known PSM Bug on Azure AD machine on 2019, consult services (Bug ID:14936)"
		}
		Else{
			$actual = $True
			$result = $True
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished NotAzureADJoinedOn2019"
	} catch {
		$errorMsg = "Could not check if server is joined to Azure Domain. Error: $(Collect-ExceptionMessage $_.Exception)"
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
# Description....: Tests network connectivity to a specific Hostname/IP on a specific port
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
				$retNetTest = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningVariable retWarning | select -ExpandProperty "TcpTestSucceeded"
				If($retWarning -like "*TCP connect to* failed" -or $retWarning -like "*Name resolution of*")
				{
					$errorMsg = "Network connectivity failed, check FW rules to '$ComputerName' on port '$Port' are allowed"
					$result = $False
				}
				Else { $result = $True }
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
		Write-LogMessage -Type Info -Msg "Attempting to retrieve Public IP, this can take up to 15 secs."
		$PublicIP = (Invoke-WebRequest -Uri ipinfo.io/ip -UseBasicParsing -TimeoutSec 5).Content
		$PublicIP | Out-File "$($env:COMPUTERNAME) PublicIP.txt"
		Write-LogMessage -Type Success -Msg "Successfully fetched Public IP: $PublicIP and saved it in a local file '$($env:COMPUTERNAME) PublicIP.txt'"
		return $PublicIP
	}
	catch{
		Throw $(New-Object System.Exception ("GetPublicIP: Couldn't grab Public IP for you, you'll have to do it manually",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ReadGPOValue
# Description....: Returns the input GPO name state
# Parameters.....: GPO XML file (as XML), GPO Name to check
# Return Values..: String, GPO State
# =================================================================================================================================
Function ReadGPOValue
{
	param(
		[XML]$gpoXML,
		[String]$gpoName
	)
	
	$PolicyName = ""
	$PolicyState = ""
	$PolicyIdentifier = ""
	$PolicyValue = ""
	
	Write-LogMessage -Type Verbose -Msg "Checking '$gpoName' in GPO report..."
	
    $extentionsDataNum = $gpoXML.Rsop.ComputerResults.ExtensionData.Count
	# Search for the gpo in the Extension Data section
	for ($extentionData = 0; $extentionData -lt $extentionsDataNum; $extentionData++)
	{
		$PoliciesNumber =  $gpoXML.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy.Count

        if ($PoliciesNumber -eq $null)
        {
           $PolicyName = $gpoXML.Rsop.ComputerResults.ExtensionData.Extension.Policy.Name

           if ($PolicyName -eq $gpoName)
			{
				$PolicyState = $gpoXML.Rsop.ComputerResults.ExtensionData.Extension.Policy.State 
				$PolicyIdentifier = $gpoXML.Rsop.ComputerResults.ExtensionData.Extension.Policy.gpo.Identifier.'#text'

				if ($gpoXML.Rsop.ComputerResults.ExtensionData.Extension.Policy.value.Name)
				{
					$PolicyValue = $gpoXML.Rsop.ComputerResults.ExtensionData.Extension.Policy.value.Name
				}
				# Exit For
				break
			}
        } else {
			for ($node = 0 ; $node -lt $PoliciesNumber; $node++)
			{
				$PolicyName = $gpoXML.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].Name

				if ($PolicyName -eq $gpoName)
				{
					$PolicyState = $gpoXML.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].State 
					$PolicyIdentifier = $gpoXML.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].gpo.Identifier.'#text'

					if ($gpoXML.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].value.Name)
					{
						$PolicyValue = $gpoXML.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].value.Name
					}

					# Exit For
					break
				}
			}
		}
	}
	Write-LogMessage -Type Verbose -Msg ("Policy Name {0} is in state {1} with current value {2}" -f $PolicyName, $PolicyState, $PolicyValue)
    return $PolicyState
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
        $cnt = $arrCheckPrerequisites.Count
		Write-LogMessage -Type Info -SubHeader -Msg "Starting checking $cnt prerequisites..."
		
        $global:table = @()
        $errorCnt = 0
        $warnCnt = 0
        $table = ""

		ForEach ($method in $arrCheckPrerequisites)
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
				#AddLineToReport $method $resultObject
			}
			else
			{
				# remove the skip description
				$resultObject.errorMsg = ""
			}
			
            AddLineToTable $method $resultObject
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

            $table = $global:table | Out-String 
            Write-LogMessage -Type Info -Msg $table			
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
	
	Write-LogMessage -Type Info -Msg "Current version is: $versionNumber"
	Write-LogMessage -Type Info -Msg "Checking for new version"
	$checkVersion = ""
	$checkVersionOK = ""
	$webVersion = New-Object System.Net.WebClient

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
		Throw $(New-Object System.Exception ("Test-VersionUpdate: Couldn't check for latest version, probably FW block",$_.Exception))
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
			Write-LogMessage -Type Info -Msg "Finished Updating, please close window (Regular or ISE) and relaunch script"
			Pause
			return
		}
		Else
		{
			Write-LogMessage -Type Error -Msg "Can't find the new script at location '$PSScriptRoot'."
		}
	}
	Else
	{
		Write-LogMessage -Type Info -Msg "Current version is the latest!"
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
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose", "Success")]
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
			"Info" { 
				Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "Magenta" } Else { "White" })
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

#endregion

#region Main Script
###########################################################################################
# Main start
###########################################################################################


#troubleshooting section
if ($Troubleshooting){BindAccount}

Write-LogMessage -Type Info -Msg $(Get-LogHeader) -Header
Write-LogMessage -Type Verbose -Msg "Verify user is a local Admin"
$adminUser = IsUserAdmin 
# Run only if the User is a local admin on the machine
If ($adminUser -eq $False)
{
	Write-LogMessage -Type Error -Msg "You must logged on as a local administrator in order to run this script"
	return
}
else
{
	Write-LogMessage -Type Verbose -Msg "User is a local Admin!"
	try {
		Write-LogMessage -Type Info -Msg "Checking for latest version"
		Test-VersionUpdate								# Check the latest version
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to check for latest version - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	try {
		Write-LogMessage -Type Verbose -Msg $(GetPublicIP)# Retrieve public IP and save it locally #TODO: For what do we need the public IP?
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to retrieve public IP - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	try {	
		CheckPrerequisites  							# Main Pre-requisites check
	} catch	{
		Write-LogMessage -Type Error -Msg "Checking prerequisites failed. Error(s): $(Collect-ExceptionMessage $_.Exception)"
	}
	try {
		GetListofDCsAndTestBindAccount					# Retrieve list of available DCs from the current machine joined domain.
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to get a list of DC - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
}
Write-LogMessage -Type Info -Msg "Script Ended" -Footer	
###########################################################################################
# Main end
###########################################################################################	
#endregion