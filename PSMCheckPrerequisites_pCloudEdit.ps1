 <#
  .DESCRIPTION
  Script checks prerequisites on the PSM server.
  .PARAMETER OutOfDomain
 
  .EXAMPLE1 
  PS C:\> .\PSMCheckPrerequisites.ps1
  
  .EXAMPLE2
  PS C:\> .\PSMCheckPrerequisites.ps1 -OutOfDomain
  
#>

[cmdletbinding()]
Param([switch]$OutOfDomain)

## configuration
##############################################################

$versionNumber = "9"

## list of checks to be performed.
$arrCheckPrerequisites = @(
"VaultConnectivity",
"TunnelConnectivity",
"CustomerPortalConnectivity",
"ConsoleConnectivity",
"CRLConnectivity",
"OSVersion",
"Processors",
"Memory",
"SQLServerPermissions",
"UsersLoggedOn",
"KBs",
"IPV6",
"PSRemoting",
"DomainUser",
"PendingRestart",
"GPO"
)


## list of GPOs to check .
$arrGPO = @(
       [pscustomobject]@{Name='Require user authentication for remote connections by using Network Level Authentication';Expected='Disabled'}
	   [pscustomobject]@{Name='Select RDP transport protocols'; Expected='Disabled'}	
       [pscustomobject]@{Name='Use the specified Remote Desktop license servers'; Expected='Disabled'}   
	   [pscustomobject]@{Name='Set client connection encryption level'; Expected='Disabled'}
	   [pscustomobject]@{Name='Use Remote Desktop Easy Print printer driver first'; Expected='Disabled'}
   )

##############################################################


#global variables
$global:table = ""
$SEPARATE_LINE = "------------------------------------------------------------------------" 
$skip = "SKIP"

Function SetExecPolicy(){
$ep = Get-ExecutionPolicy
if ($ep -ne "Bypass")
{
Set-ExecutionPolicy RemoteSigned -Force
}
}

Function GetListofDCsAndTestBindAccount()
{
$UserPrincipal = DomainUser
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

Function GetPublicIP(){
$PublicIP = ""

Try{
Write-Host "Attempting to retrieve Public IP, this can take upto 15 secs." -ForegroundColor DarkCyan
$PublicIP = (Invoke-WebRequest -Uri ipinfo.io/ip -UseBasicParsing -TimeoutSec 5).Content
}
Catch{
}

If ($PublicIP){
Write-Host "Successfully fetched Public IP: $PublicIP and saved it in a local file '$env:COMPUTERNAME PublicIP.txt'" -ForegroundColor Cyan
$PublicIP | Out-File "$env:COMPUTERNAME PublicIP.txt"
}
Else
{
Write-Host "Couldn't grab Public IP for you, you'll have to do it manually"
}
}

function OSVersion()
{

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

    [PsCustomObject]@{
        expected = "Windows Server 2016/2019";
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}

function IPV6()
{

    $expected = "Disabled"
    $actual = ""
    $result = $false
    $errorMsg = ""

    #Disable IPv6 on NIC
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

    #Disable IPv6 on Registry
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "0" -PropertyType DWORD -Force

    $IPV6 = $false
    $arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress

    foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains(":")}

    if($IPV6)
    {
        $actual = "Enabled"
        $result = $false
    }
    else 
    {
        $actual = "Disabled"
        $result = $true
    }

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}

function PSRemoting()
{
    $expected = "Enabled"
    $actual = ""	
    $result = $false
	$errorMsg = ""

    try 
    {
        $computerName = $env:COMPUTERNAME
        $null = Invoke-Command -ComputerName $computerName -ScriptBlock { ; } -ErrorAction Stop
        $actual = "Enabled"	
        $result = $true
    } 
    catch 
    {
        $actual = "Disabled"
        $result = $false
		        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
				$UserMemberOfProtectedGroup = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current.GetGroups().Name -match "Protected Users"
				if ($UserMemberOfProtectedGroup)
				{
				$errorMsg = "Detected in 'Protected Users' group in AD, remove from group."
				}
    }
    
    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}

function KBs()
{
    $expected = "Installed"
    $actual = ""
    $errorMsg = ""
    $otherOS = $false
    $result = $false

    $hotFixes = ""
    $osVersionName  = (Get-WmiObject Win32_OperatingSystem).caption
    $osVersion = [System.Environment]::OSVersion.Version
	
    if ($osVersion.Major -eq 10)
    {
        # currently there are no KBs to check on win 2016
        $hotFixes = ""
    }
    elseif (($osVersion.Major -eq 6) -And ($osVersion.Minor -eq 3) -And ($osVersion.Build -eq 9600))
    {
        $hotFixes = 'KB2919355','KB3154520'
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
            $errorMsg = $skip
            $result =  $true
        }
	 
        else
        {
            $pcHotFixes = Get-HotFix $hotFixes -EA ignore | select -Property HotFixID 
	
            #non of the KBs installed
            if($pcHotFixes -eq $null)
            {
            	$errorMsg = "KBs not installed: $hotFixes"
            	$actual = "Not Installed"
            	$result = $false
            }

            else
            {	
            	$count = $pcHotFixes | measure 

            	$strPcHotFixes = [system.String]::Join(" ",$pcHotFixes)
            	$HotfixesNotInstalled = ""
	
            	if($hotFixes.Count -ne $count.Count)
            	{
                    ForEach ($hotFix in $hotFixes)
                    {
	                    if($strPcHotFixes.Contains($hotFix))
	                    {

	                    }
	                    else
	                    {
		                    $HotfixesNotInstalled += $hotFix + " "
	                    }
                    }
		
                    $errorMsg = "KBs not installed: $HotfixesNotInstalled"
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

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}


function  ServerInDomain()
{
    $expected = "In Domain"
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

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = "";
        result = $result;
    }
}	

function  DomainUser()
{
    $expected = "Domain user"
    $result = $false
    
    if ($OutOfDomain) 
    {
        $errorMsg = $skip
        $result = $true
    }
    
    else
    {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	    $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current

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

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = "";
        result = $result;
    }
    return $UserPrincipal
}

function IsUserAdmin()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $rc = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
    return $rc
}


function PendingRestart()
{
    $expected = "Not pending restart"
    $actual = "Pending restart"
    $result = $false

	$computer = $env:COMPUTERNAME		
    
	$HKLM = [UInt32] "0x80000002"
	$reg = [WMIClass] "\\$computer\root\default:StdRegProv"
						

    $keys = $reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
	$pendingRestart = $keys.sNames -contains "RebootPending"
    
    if($pendingRestart)
    {
        $result = $false
    }	
	    
    else
    {							    
        $keys = $reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
        $pendingRestart = $RegWUAURebootReq.sNames -contains "RebootRequired"
    
        if($pendingRestart)
        {
            $result = $false
        }
						
        else
        {
            $keys = $reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
            $pendingRestart = $RegSubKeySM.sValue
		
            if($pendingRestart)
            {
                $result = $false
            }
            else 
            {
                try { 
                   $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
                   $status = $util.DetermineIfRebootPending()

                   if(($status -ne $null) -and $status.RebootPending){
         
                     $result = $false
                   }
                   else
                   {
                    $result = $true
                    $actual = "Not Pending restart"
                   }
                }catch{ 
                    $result = $true      
                    $actual = "Not Pending restart"
                }
            }
        }
    }

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = "";
        result = $result;
    }
}	

function UsersLoggedOn()
{
    $expected = "Only one user is logged on"
    $actual = ""
    $errorMsg = ""
    $result = $false
        
    try { 
       
         $computerName = $env:COMPUTERNAME

         $ActiveUsers = query.exe user /server $ComputerName
         $numOfActiveUsers = ($ActiveUsers | measure).Count
         
         if($numOfActiveUsers -ne 2)
         {
            WriteLogI $scriptName $ActiveUsers $false
            $errorMsg = "Please see log for details"
            $actual = "More than one user is logged on"
            $result = $false

         }
         else
         {
            $actual = $expected
            $result = $true
         }
          
       
    }catch{
    
        WriteLogE $scriptName "UsersLoggedOn - cannot check if another user is logged on" $false 
        $errorMsg = $skip
        $result = $false
    }

    [PsCustomObject]@{
        expected = $expected;
        actual =   $actual;
        errorMsg = $errorMsg;
        result = $result;
    }

}	

function GPO()
{
   $expected = "PSM Compatible"
   $actual = ""	
   $errorMsg = ""
   $result = $false
   $gpoResult = $false
   $compatible = $true

   $path = "C:\Windows\temp\GPOReport.xml"
   gpresult /f /x $path *> $null
    
   WriteLogAndReturnCursor ""
    
    [xml]$xml = Get-Content $path

	if($arrGPO.Count -gt 0)
	{

            ForEach ($gpo in $arrGPO)
            {
            	$errorMsg = ""
            	$GPOValueResult = ReadGPOValue $gpo.Name 

            	if ($GPOValueResult -eq "")
            	{
                	$actual = "Not Configured"
                	$gpoResult = $true
            	}
            	else
            	{
                	$actual = $GPOValueResult

	                $gpoResult =  ($gpo.Expected -eq $GPOValueResult)

                
        	        if(-not $gpoResult )
                	{
	                    $compatible = $false
	                    $errorMsg = "Expected:"+$gpo.Expected+"  Actual:"+$actual
                	}
            	}
			
            	$name = "GPO: "+$gpo.Name
            	$reportObj = @{expected = $gpo.Expected; actual =   $actual; errorMsg = $errorMsg; result = $gpoResult;}
            	AddLineToReport $name $reportObj

            }#loop end
	}

	$errorMsg = $skip
    if(!$compatible)
    {
         $actual = "Not Compatible"
         $result = $false
    }
    else
    {
       $result = $true
    }

    [PsCustomObject]@{
        expected = $expected;
        actual =   $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}


function ReadGPOValue ($gpoName)
{

    $extentionsDataNum = $xml.Rsop.ComputerResults.ExtensionData.Count
	
	for ($extentionData = 0; $extentionData -lt $extentionsDataNum; $extentionData++)
	{
	
		$PoliciesNumber =  $xml.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy.Count

        if ($PoliciesNumber -eq $null)
        {
           $PolicyName = $xml.Rsop.ComputerResults.ExtensionData.Extension.Policy.Name

           if ($PolicyName -eq $gpoName)
			{
				$PolicyState = $xml.Rsop.ComputerResults.ExtensionData.Extension.Policy.State 
				$PolicyIdentifier = $xml.Rsop.ComputerResults.ExtensionData.Extension.Policy.gpo.Identifier.'#text'

				if ($xml.Rsop.ComputerResults.ExtensionData.Extension.Policy.value.Name)
				{
					$PolicyValue = $xml.Rsop.ComputerResults.ExtensionData.Extension.Policy.value.Name
				}

				return $PolicyState
			}


        }
		$PolicyName = ""
		$PolicyState = ""
		$PolicyIdentifier = ""
		$PolicyValue = ""

        for ($node = 0 ; $node -lt $PoliciesNumber; $node++)
		{
			$PolicyName = $xml.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].Name

			if ($PolicyName -eq $gpoName)
			{
				$PolicyState = $xml.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].State 
				$PolicyIdentifier = $xml.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].gpo.Identifier.'#text'

				if ($xml.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].value.Name)
				{
					$PolicyValue = $xml.Rsop.ComputerResults.ExtensionData[$extentionData].Extension.Policy[$node].value.Name
				}

				return $PolicyState
			}
		}
	}
    return ""
}

function WriteLogAndReturnCursor($msg)
{

    Write-Host "                                                                     "
    $pos = $host.UI.RawUI.CursorPosition
    $pos.Y -= 1
    $host.UI.RawUI.CursorPosition =  $pos

    WriteLogI $scriptName $msg $true
    $pos = $host.UI.RawUI.CursorPosition
    $pos.Y -= 1
    $host.UI.RawUI.CursorPosition =  $pos

}

function AddLineToTable($action, $resultObject)
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

function AddLineToReport($action, $resultObject)
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
            WriteLogW $scriptName $line $true 
        }
        else
        { 
            WriteLogS $scriptName $line $true 
        }
    }
    else
    {
        $mark = '[X]'
        $line = "$mark $actionPad $errMessage"
        WriteLogE $scriptName $line $true 
    }

}
 


function CheckPrerequisites()
{

	Try
	{

        $cnt = $arrCheckPrerequisites.Count
		WriteLogI $scriptName "PSMCheckPrerequisites version:$versionNumber" $true 
		WriteLogH $scriptName "Checking prerequisites start..." $true 
		

        $global:table = @()
        $errorCnt = 0
        $warnCnt = 0
        $table = ""


		ForEach ($method in $arrCheckPrerequisites)
        {
            Try
            { 
                WriteLogAndReturnCursor "Checking $method..."
                $resultObject = &$method  

                if(!$resultObject.result)
                {
                    $errorCnt++
                }

                WriteLogAndReturnCursor ""
                WriteLogI $scriptName "End $method" $false             
            }
            Catch
            {
                $resultObject.errorMsg = $_.Exception.Message
                $errorCnt++
            }

			if($resultObject.errorMsg -ne $skip)
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
        
        WriteLogI $scriptName "`n`n`n`n$SEPARATE_LINE" $true
		
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


			WriteLogI $scriptName "Checking Prerequisites completed with $errorCnt $errorStr and $warnCnt $warnStr " $true

            WriteLogI $scriptName "$SEPARATE_LINE" $true
            $global:table | Format-Table  

            $table = $global:table | Out-String      
            WriteLogI $scriptName $table $false 
            
			
        }
        else
        {
            WriteLogS $scriptName "Checking Prerequisites completed successfully" $true
        }

        WriteLogI $scriptName "$SEPARATE_LINE" $true
				
	}
	Catch
	{
		WriteLogE $scriptName "Failed to run CheckPrerequisites" $true 
		WriteLogE $scriptName  $_.Exception.Message > $null
		throw ($_.Exception.Message)
	}
}






	
function InitLogfileHeaderAndSetLogParams ($stageName)
{
    $FileHeader = @"
###########################################################################################
#
#                       PSM $stageName PowerShell Script
#
#
#
#
# Created : Nov 2019
# Modified:3/11/2019
# Version : $versionNumber
# CyberArk Software Ltd.
###########################################################################################

"@
	$logDate = $(get-date -format yyyyMMdd) + "-" + $(get-date -format HHmmss)
    $logfile = "$env:windir\Temp\PSMCheckPrerequisites$logDate.log"	
    SetLogParams $logfile "PSM" "" $fileHeader	
}	
	
	
#logPathParam 		= log file path including filename 
#componentNameParam = CPM/PVWA/PSM
#scriptTypeParam    = PO (for post installation) / PR (for pre installation) / IN (for installation) / HA (for hardening)
#fileHeaderParam    = the header that will be displayed at the top of the logfile

function SetLogParams([string]$logPathParam, [string]$componentNameParam, [string]$scriptTypeParam, [string]$fileHeaderParam)
{
	$global:LogPath = $logPathParam
	$global:ComponentName = $componentNameParam
	$global:ScriptType = $scriptTypeParam
	$global:FileHeader = $fileHeaderParam
}

#Writing to log file
#scriptName 	= the name of the calling script
#info       	= the log message content
#writeToScreen 	= true if this message should be also written to screen
#color         	= true if this message on screen will be colored
function WriteLogE([string]$scriptName, [string]$info, [bool]$writeToScreen)
{
	WriteLog $scriptName "ERR"  $info $writeToScreen
}

function WriteLogW([string]$scriptName, [string]$info, [bool]$writeToScreen)
{
	WriteLog $scriptName "WAR" $info $writeToScreen
}

function WriteLogI([string]$scriptName, [string]$info, [bool]$writeToScreen)
{
	WriteLog $scriptName "INF" $info $writeToScreen
}

function WriteLogS([string]$scriptName, [string]$info, [bool]$writeToScreen)
{
	WriteLog $scriptName "SUC" $info $writeToScreen
}

function WriteLogH([string]$scriptName, [string]$info, [bool]$writeToScreen)
{
    WriteLog $scriptName "HED" "" $writeToScreen	
    WriteLog $scriptName "HED" $info $writeToScreen
    WriteLog $scriptName "HED" "" $writeToScreen
}
function WriteLog([string]$scriptName, [string]$logLevel, [string]$info, [bool]$writeToScreen)
{         
   if($global:loginitialized -eq $false)
   {            
      $FileHeader > $global:LogPath
      $global:loginitialized = $true            
   } 
   $Stamp = $(get-date -format yyyy-MM-dd) + " " + $(get-date -format HH:mm:ss:fff) + " - " + $global:ComponentName + " " + $global:ScriptType + " " + $scriptName + " " + $logLevel + " - "
   $Stamp + $info >> $global:LogPath     
   write-debug $info
   <#
   if ($verbose)
   {
      write-verbose $info -verbose
   }
   #>

   if ($writeToScreen)
   {
	  $colorType=""
	  switch ($logLevel)
	  {
		"ERR" { $colorType='red'}
		"WAR" { $colorType='yellow'}
		"INF" { $colorType='white' }
		"SUC" { $colorType='green' }
		"HED" { $colorType='Magenta' }
	  }

     Write-Host($info) -foreground  $colorType
   }
} 	

function VaultConnectivity()
{
$expected = "True"
$actual = ""
$result = $false
$errorMsg = ""
$VaultIPerror = ""

$VaultIP = Read-Host "Please enter your Vault IP Address (Leave empty if you don't have it)"
    If ($VaultIP) 
    {
    $actual = Test-NetConnection -ComputerName $VaultIP -Port 1858 -WarningVariable VaultIPerror | select -ExpandProperty "TcpTestSucceeded"
    $result = $actual
        If ($VaultIPerror -like "*TCP connect to* failed")
        {
        $errorMsg = "Connectivity to Vault failed, check FW rule is whitelisted"
        $result = $false
        }
    }
    Else
    {
    $errorMsg = "No Vault IP entered, ignoring this check"
    $result = $false
    }
    

        [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
    }

    function TunnelConnectivity()
{
$expected = "True"
$actual = ""
$result = $false
$errorMsg = ""
$TunnelIPerror = ""

$TunnelIP = Read-Host "Please enter your TunnelConnector IP Address (Leave empty if you don't have it)"
    If ($TunnelIP) 
    {
    $actual = Test-NetConnection -ComputerName $TunnelIP -Port 5511 -WarningVariable TunnelIPerror | select -ExpandProperty "TcpTestSucceeded"
    $result = $actual
        If ($TunnelIPerror -like "*TCP connect to* failed")
        {
        $errorMsg = "Connectivity to TunnelConnector failed, check FW rule is whitelisted"
        $result = $false
        }
    }
    Else
    {
    $errorMsg = "No TunnelConnector IP entered, ignoring this check"
    $result = $false
    }
    

        [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
    }


Function ConsoleConnectivity()
{
$expected = "True"
$actual = ""
$result = $false
$errorMsg = ""
$ConsoleIPerror = ""
$ConsoleIP = "console.privilegecloud.cyberark.com"

    $actual = Test-NetConnection -ComputerName $ConsoleIP -Port 443 -WarningVariable ConsoleIPerror | select -ExpandProperty "TcpTestSucceeded"
    $result = $actual
        If ($ConsoleIPerror -like "*TCP connect to* failed" -or $ConsoleIPerror -like "*Name resolution of*")
        {
        $errorMsg = "Connectivity to Cloud Console (https://console.privilegecloud.cyberark.com) failed, check FW rules and DNS configuration"
        $result = $false
        }

    

        [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
    }

Function CRLConnectivity()
{
$expected = "200"
$actual = ""
$result = $false
$errorMsg = ""


$cert1 = 0
$cert2 = 0
Try{
$cert1 = Invoke-WebRequest -Uri http://crl3.digicert.com/CloudFlareIncECCCA2.crl -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing  | select -ExpandProperty StatusCode
$cert2 = Invoke-WebRequest -Uri http://crl4.digicert.com/CloudFlareIncECCCA2.crl -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing | select -ExpandProperty StatusCode

    If($cert1 -and $cert2 -eq 200)
    {
        $actual = $expected
        $result = $true
    }
    }
    catch 
    {
    if ($Error[0].ErrorDetails.Message -eq "404 - Not Found"){
    $errorMsg = "Can't find CRL file on target site, was it changed? Contact CyberArk"
    #Write-Host "Can't find CRL file on target site, was it changed? Contact CyberArk"
    }
    $Error[0].Exception.Message
    $errorMsg = "Can't resolve hostname (digicert.com), check DNS settings"
    }

    

        [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
    }

        function CustomerPortalConnectivity()
{
$expected = "True"
$actual = ""
$result = $false
$errorMsg = ""
$PortalURLerror = ""

$ConnectionDetailsFile = "$PSScriptRoot\*ConnectionDetails.txt"

if (Test-Path $ConnectionDetailsFile){
    $PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:")).Host
    }
else{
$PortalURL = Read-Host "Please enter your provided portal URL Address, Example: https://<customerDomain>.privilegecloud.cyberark.com (Leave empty if you don't have it)"
}


    If ($PortalURL) 
    {
       if ($PortalURL -match "https://")
       {
       $PortalURL = ([System.Uri]$PortalURL).Host
       }
    $actual = Test-NetConnection -ComputerName $PortalURL -Port 443 -WarningVariable PortalURLerror | select -ExpandProperty "TcpTestSucceeded"
    $result = $actual
        If ($PortalURLerror -like "*TCP connect to* failed")
        {
        $errorMsg = "Connectivity to TunnelConnector failed, check FW rule is whitelisted"
        $result = $false
        }
    }
    Else
    {
    $errorMsg = "No Portal URL entered, ignoring this check"
    $result = $false
    }
    

        [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
    }



function  Processors()
{
    $expected = "True"
    $actual = ""
    $result = $false
    $errorMsg = ""
    
    if ((Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors -ge "8")
    {
          $actual = "True"
          $result = $true
    } 
    else 
    {
          $actual = "False"
          $result = $false
          $errorMsg = "Less than minimum (8) cores detected"
    }

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}
	
function  Memory()
{
    $expected = "True"
    $actual = ""
    $result = $false
    $errorMsg = ""
    $Memory = [math]::Round(((Get-CimInstance CIM_PhysicalMemory).Capacity | Measure-Object -Sum).Sum / 1GB, 2)
    $MemoryAWS = [math]::Round((Get-CimInstance -ClassName CIM_ComputerSystem).TotalPhysicalMemory / 1GB, 0)
    
    if ($Memory -ge 8 -or $MemoryAWS -ge 8)
    {
          $actual = "True"
          $result = $true
    } 
    else 
    {
          $actual = "False"
          $result = $false
          $errorMsg = "Less than minimum (8) RAM detected"
    }

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}	

function  SQLServerPermissions()
{
    $expected = "True"
    $actual = ""
    $result = $false
    $errorMsg = ""

$SecPolGPO = @{
    "SeDebugPrivilege" = "Debug Programs"
    "SeBackupPrivilege" = "Back up files and directories"
    "SeSecurityPrivilege" = "Manage auditing and security log"
}

    
    $path = "C:\Windows\Temp\SecReport.txt"
    SecEdit /areas USER_RIGHTS /export /cfg $path

    $SecPol = gc $path

foreach ($sec in $SecPolGPO.Keys) {
    $administrators = Select-String $path -Pattern $sec
        if($administrators -eq $null)
            {
        $actual = "False"
        $errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
        $result = $false
            }
        else
        {
           foreach ($admin in $administrators)
           {
        if ($admin -like "*S-1-5-32-544*")
           {
        $actual = "True"
        $result = $actual
            }
        else
            {
        $actual = "False"
        $errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
        $result = $false
            }
            }
        }

    }


    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}


function versionUpdate(){
Write-Host "Current version is: $versionNumber"
Write-Host "Checking for new version" -ForegroundColor DarkCyan
$checkVersion = ""
$checkVersionOK = ""
$webVersion = New-Object System.Net.WebClient

Try
{
$checkVersionOK = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pCloudServices/ps/master/Latest.txt" -ErrorAction SilentlyContinue).StatusCode

If ($checkVersionOK -eq "200"){
$checkVersion = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pCloudServices/ps/master/Latest.txt" -ErrorAction SilentlyContinue).Content.toString().trim()
}
}
Catch
{
write-host "Couldn't reach Github (404), probably FW block" -ForegroundColor DarkCyan
}

If ($checkVersionOK -eq "200"){
    if ($checkVersion -gt $versionNumber){
    Write-Host "Found new version: $checkVersion Updating..." -ForegroundColor DarkCyan
    Try
    {
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pCloudServices/ps/master/PSMCheckPrerequisites_pCloudEdit.ps1" -ErrorAction SilentlyContinue -OutFile "$PSCommandPath.NEW"
    }
    Catch
    {
    write-host "Couldn't reach Github (404), probably FW block" -ForegroundColor DarkCyan
    }

            if (Test-Path -Path "$PSCommandPath.NEW"){
            Rename-Item -path $PSCommandPath -NewName "$PSCommandPath.OLD"
            Rename-Item -Path "$PSCommandPath.NEW" -NewName "PSMCheckPrerequisites_PrivilegeCloud.ps1"
	        Remove-Item -Path "$PSCommandPath.OLD"
            Write-Host "Finished Updating, please close window (Regular or ISE) and relaunch script" -ForegroundColor DarkCyan
            Pause
            Exit
            }
            else
            {
            Write-Host "Can't find the new script at location '$PSScriptRoot'."
            }
            }
            Else
            {
            Write-Host "Current version is latest!" -ForegroundColor DarkCyan
            }
}
Else
{
Write-Host "Couldn't check for new script version, resuming in offline mode" -ForegroundColor DarkCyan
}
}
	

	
###########################################################################################
# Main start
###########################################################################################


	Try
	{	
        InitLogfileHeaderAndSetLogParams 'CheckPrerequisites'
        [string]$myDate =  $(get-date -format yyyy-MM-dd) + " "+ $(get-date -format HH:mm:ss:fff) ;
		WriteLogI $scriptName $myDate $true
        $adminUser = IsUserAdmin 

        If ($adminUser -eq $False)
		{
			WriteLogE $scriptName "You must login as an administrator user in order to run this script" $true
		}
		else
		{
            versionUpdate		#check if latest version
            GetPublicIP			#retrieve public IP and save it locally
		    CheckPrerequisites
            GetListofDCsAndTestBindAccount		#retrieve list of available DCs from the current machine joined domain.
		}
        
        
	}
	Catch
	{
		WriteLogE $scriptName "Checking prerequisites failed" $true 
		WriteLogE $scriptName  $_.Exception.Message > $null
		throw ($_.Exception.Message)
	}	



###########################################################################################
# Main end
###########################################################################################	

# SIG # Begin signature block
# MIIfdgYJKoZIhvcNAQcCoIIfZzCCH2MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBDS0qGZyj0dO9p
# HHMk8RujVdbTvdtOZsoH1XdJ49yTpqCCDnUwggROMIIDNqADAgECAg0B7l8Wnf+X
# NStkZdZqMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9i
# YWxTaWduIFJvb3QgQ0EwHhcNMTgwOTE5MDAwMDAwWhcNMjgwMTI4MTIwMDAwWjBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRf
# JMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpi
# Lx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR
# 5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hp
# sk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Sa
# er9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaOCASIwggEeMA4GA1Ud
# DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSP8Et/qC5FJK5N
# UPpjmove4t0bvDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzA9Bggr
# BgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL3Jvb3RyMTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL3Jvb3QuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG
# 9w0BAQsFAAOCAQEAI3Dpz+K+9VmulEJvxEMzqs0/OrlkF/JiBktI8UCIBheh/qvR
# XzzGM/Lzjt0fHT7MGmCZggusx/x+mocqpX0PplfurDtqhdbevUBj+K2myIiwEvz2
# Qd8PCZceOOpTn74F9D7q059QEna+CYvCC0h9Hi5R9o1T06sfQBuKju19+095VnBf
# DNOOG7OncA03K5eVq9rgEmscQM7Fx37twmJY7HftcyLCivWGQ4it6hNu/dj+Qi+5
# fV6tGO+UkMo9J6smlJl1x8vTe/fKTNOvUSGSW4R9K58VP3TLUeiegw4WbxvnRs4j
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBKcwggOPoAMCAQICDkgbagep
# Qkweqv7zzfEPMA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTE2MDYxNTAwMDAwMFoXDTI0MDYxNTAwMDAwMFowbjELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExRDBCBgNVBAMTO0dsb2Jh
# bFNpZ24gRXh0ZW5kZWQgVmFsaWRhdGlvbiBDb2RlU2lnbmluZyBDQSAtIFNIQTI1
# NiAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2be6Ja2U81u+
# QQYcU8oMEIxRQVkzeWT0V53k1SXE7FCEWJhyeUDiL3jUkuomDp6ulXz7xP1xRN2M
# X7cji1679PxLyyM9w3YD9dGMRbxxdR2L0omJvuNRPcbIirIxNQduufW6ag30EJ+u
# 1WJJKHvsV7qrMnyxfdKiVgY27rDv0Gqu6qsf1g2ffJb7rXCZLV2V8IDQeUbsVTrM
# 0zj7BAeoB3WCguDQfne4j+vSKPyubRRoQX92Q9dIumBE4bdy6NDwIAN72tq0BnXH
# sgPe+JTGaI9ee56bnTbgztJrxsZr6RQitXF+to9aH9vnbvRCEJBo5itFEE9zuizX
# xTFqct1jcwIDAQABo4IBYzCCAV8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQG
# CCsGAQUFBwMDBggrBgEFBQcDCTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBTcLFgsKm81LZ95lahIXcRtPlO/uTAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpj
# move4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3Nw
# Mi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDov
# L2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBiBgNVHSAEWzBZMAsGCSsG
# AQQBoDIBAjAHBgVngQwBAzBBBgkrBgEEAaAyAV8wNDAyBggrBgEFBQcCARYmaHR0
# cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEL
# BQADggEBAHYJxMwv2e8eS6n4V/NAOSHKTDwdnikrINQrRNKIzhoNBc+Dgbvrabwx
# jSrEx0TMYGCUHM+h4QIkDq1bvizCJx5nt+goHzJR4znzmN+4ny6LKrR7CgO8vTYE
# j8nQnE+jAieZsPBF6TTf5DqjtwY32G8qeZDU1E5YcexTqWGY9zlp4BKcV1hyhicp
# pR3lMvMrmZdavyuwPLQG6g5k7LfNZYAkF8LZN/WxJhA1R3uaArpUokWT/3m/GozF
# n7Wf33jna1DxR5RpSyS42gXoDJ1PBuxKMSB+T12GhC81o82cwYRXHx+twOKkse8p
# ayGXptT+7QM3sPz1jSq83ISD497D518wggV0MIIEXKADAgECAgwhXYQh+9kPSKH6
# QS4wDQYJKoZIhvcNAQELBQAwbjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExRDBCBgNVBAMTO0dsb2JhbFNpZ24gRXh0ZW5kZWQgVmFsaWRh
# dGlvbiBDb2RlU2lnbmluZyBDQSAtIFNIQTI1NiAtIEczMB4XDTE5MDQwMjE0MDI0
# NVoXDTIyMDQwMjE0MDI0NVowgcgxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
# aW9uMRIwEAYDVQQFEwk1MTIyOTE2NDIxEzARBgsrBgEEAYI3PAIBAxMCSUwxCzAJ
# BgNVBAYTAklMMRkwFwYDVQQIExBDZW50cmFsIERpc3RyaWN0MRQwEgYDVQQHEwtQ
# ZXRhaCBUaWt2YTEfMB0GA1UEChMWQ3liZXJBcmsgU29mdHdhcmUgTHRkLjEfMB0G
# A1UEAxMWQ3liZXJBcmsgU29mdHdhcmUgTHRkLjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAJmp1fuFtNzvXmXAG4MZy5nl5gLRMycA6ieFpbOIPdMOTMvO
# wWaW4VASvtzqyZOpUNV0OZka6ajkVrM7IzihX43zvfEizWmG+359QU6htgHSWmII
# KDjEOxQrnq/+l0qgbBge6zqA4mzXh+frgpgnfvL9Rq7WTCjNywTl7UD3mn5VuKbZ
# XIhn19ICv7WKSr/VVoGNpIy/o3PmgHLfSMX9vUaxU+sXIZKhP1eqFtMMllO0jzK2
# hAttOAGLlKJO2Yp17+HOI86vfVAJ8YGOeFdtObgdrL/DhSORMFZE5Y5eT14vLZQu
# OODTz/YZE/PnrwxGKFqPQNHo9O7/j4kNxGTa1m8CAwEAAaOCAbUwggGxMA4GA1Ud
# DwEB/wQEAwIHgDCBoAYIKwYBBQUHAQEEgZMwgZAwTgYIKwYBBQUHMAKGQmh0dHA6
# Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZXh0ZW5kY29kZXNpZ25z
# aGEyZzNvY3NwLmNydDA+BggrBgEFBQcwAYYyaHR0cDovL29jc3AyLmdsb2JhbHNp
# Z24uY29tL2dzZXh0ZW5kY29kZXNpZ25zaGEyZzMwVQYDVR0gBE4wTDBBBgkrBgEE
# AaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20v
# cmVwb3NpdG9yeS8wBwYFZ4EMAQMwCQYDVR0TBAIwADBFBgNVHR8EPjA8MDqgOKA2
# hjRodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZXh0ZW5kY29kZXNpZ25zaGEy
# ZzMuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQQP3rH7GUJCWmd
# tvKh9RqkZNQaEjAfBgNVHSMEGDAWgBTcLFgsKm81LZ95lahIXcRtPlO/uTANBgkq
# hkiG9w0BAQsFAAOCAQEAtRWdBsZ830FMJ9GxODIHyFS0z08inqP9c3iNxDk3BYNL
# WxtU91cGtFdnCAc8G7dNMEQ+q0TtQKTcJ+17k6GdNM8Lkanr51MngNOl8CP6QMr+
# rIzKAipex1J61Mf44/6Y6gOMGHW7jk84QxMSEbYIglfkHu+RhH8mhYRGKGgHOX3R
# ViIoIxthvlG08/nTux3zeVnSAmXB5Z8KJ+FTzLyZhFii2i2TLAt/a95dMOb4YquH
# qK9lmeFCLovYNIAihC7NHBruSGkt/sguM/17JWPpgHpjJxrIZH3dVH41LNPb3Bz2
# KDHmv37ZRpQvuxAyctrTAPA6HJtuEJnIo6DhFR9LfTGCEFcwghBTAgEBMH4wbjEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExRDBCBgNVBAMT
# O0dsb2JhbFNpZ24gRXh0ZW5kZWQgVmFsaWRhdGlvbiBDb2RlU2lnbmluZyBDQSAt
# IFNIQTI1NiAtIEczAgwhXYQh+9kPSKH6QS4wDQYJYIZIAWUDBAIBBQCgfDAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgzM3UVhdyz5nn
# CYC25H8bIN4tjJssp6W8iguFgnCn/uYwDQYJKoZIhvcNAQEBBQAEggEAfbx8bNoO
# 8rorCxQQKh81fb2mDFkkIXVFKaVDpgEXnXFlpgosk/8cPCNE12vN2gpnrEJdj6Xy
# 41ICAV8rR8/mfYRMr6lOdrkJEEvo07DGdowXgCJmBNCVSXBqIBb30Bob0j4zfSbl
# /8U4B8eI5QF3NcpJ7BMjqK/BuaZRpb0UQY0J/2f8+5JDLZ4TlgAS3Vd43cklBvJR
# 7pOrxoHHMbQOw0VHN4+ZwM2uUoP6vQiowp6dgvWGB8r+rRwoGjGnrjBsBdiklGzk
# /SFueYUgdiy3PaoUo+0/ZPdSE7e3eGTTVjNUlKhgauytDRNBk1z6iN9CCOgW4wR3
# OA2rVA9lv37TlKGCDiwwgg4oBgorBgEEAYI3AwMBMYIOGDCCDhQGCSqGSIb3DQEH
# AqCCDgUwgg4BAgEDMQ0wCwYJYIZIAWUDBAIBMIH/BgsqhkiG9w0BCRABBKCB7wSB
# 7DCB6QIBAQYLYIZIAYb4RQEHFwMwITAJBgUrDgMCGgUABBQFS75sPbp8X2lRadT6
# VGkmUM8ggQIVAKgpv8+HgDlbPiyE+s9ENCWc7VmnGA8yMDIwMDUxNDEwNDAzMlow
# AwIBHqCBhqSBgzCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENv
# cnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYD
# VQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIFNpZ25lciAtIEczoIIK
# izCCBTgwggQgoAMCAQICEHsFsdRJaFFE98mJ0pwZnRIwDQYJKoZIhvcNAQELBQAw
# gb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UE
# CxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDggVmVy
# aVNpZ24sIEluYy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE4MDYGA1UEAxMv
# VmVyaVNpZ24gVW5pdmVyc2FsIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw
# HhcNMTYwMTEyMDAwMDAwWhcNMzEwMTExMjM1OTU5WjB3MQswCQYDVQQGEwJVUzEd
# MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
# IFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+d
# jHJdGoGi61XzsAGtPHGsMo8Fa4aaJwAyl2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4
# Yht+66YH4t5/Xm1AONSRBudBfHkcy8utG7/YlZHz8O5s+K2WOS5/wSe4eDnFhKXt
# 7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9IThxNF8ccYGKbQ/5IMNJsN7CD5N+Qq3M0n/
# yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+vJJXcnf0zajM/gn1kze+lYhqxdz0sUvU
# zugJkV+1hHk1inisGTKPI8EyQRtZDqk+scz51ivvt9jk1R1tETqS9pPJnONI7rtT
# DtQ2l4Z4xaE3AgMBAAGjggF3MIIBczAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/
# BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBz
# Oi8vZC5zeW1jYi5jb20vcnBhMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYS
# aHR0cDovL3Muc3ltY2QuY29tMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5
# bWNiLmNvbS91bml2ZXJzYWwtcm9vdC5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# KAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTMwHQYDVR0O
# BBYEFK9j1sqjToVy4Ke8QfMpojh/gHViMB8GA1UdIwQYMBaAFLZ3+mlIR59TEtXC
# 6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUAA4IBAQB16rAt1TQZXDJF/g7h1E+meMFv
# 1+rd3E/zociBiPenjxXmQCmt5l30otlWZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9
# HJFHyeLojQP7zJAv1gpsTjPs1rSTyEyQY0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NX
# QZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72a433Snq+8839A9fZ9gOoD+NT9wp17MZ1
# LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnjOgC/zoqUywHbnsc4uw9Sq9HjlANgCk2g
# /idtFDL8P5dA4b+ZidvkORS92uTTw+orWrOVWFUEfcea7CMDjYUq0v+uqWGBMIIF
# SzCCBDOgAwIBAgIQe9Tlr7rMBz+hASMEIkFNEjANBgkqhkiG9w0BAQsFADB3MQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
# BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNI
# QTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMTcxMjIzMDAwMDAwWhcNMjkwMzIyMjM1
# OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0
# aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhT
# eW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIFNpZ25lciAtIEczMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArw6Kqvjcv2l7VBdxRwm9jTyB+HQVd2eQ
# nP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRok
# KPgbclE9yAmIJgg6+fpDI3VHcAyzX1uPCB1ySFdlTa8CPED39N0yOJM/5Sym81kj
# y4DeE035EMmqChhsVWFX0fECLMS1q/JsI9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS
# 41dsIr9Vf2/KBqs/SrcidmXs7DbylpWBJiz9u5iqATjTryVAmwlT8ClXhVhe6oVI
# QSGH5d600yaye0BTWHmOUjEGTZQDRcTOPAPstwDyOiLFtG/l77CKmwIDAQABo4IB
# xzCCAcMwDAYDVR0TAQH/BAIwADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEww
# IwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwIC
# MBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0
# dHA6Ly90cy1jcmwud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3MtY2EuY3JsMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDB3BggrBgEFBQcB
# AQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVjLmNv
# bTA7BggrBgEFBQcwAoYvaHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vc2hh
# MjU2LXRzcy1jYS5jZXIwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFt
# cC0yMDQ4LTYwHQYDVR0OBBYEFKUTAamfhcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQY
# MBaAFK9j1sqjToVy4Ke8QfMpojh/gHViMA0GCSqGSIb3DQEBCwUAA4IBAQBGnq/w
# uKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5Rk7nfmUGWIu8V4qSDQjYELo2JPoKe/s7
# 02K/SpQV5oLbilRt/yj+Z89xP+YzCdmiWRD0Hkr+Zcze1GvjUil1AEorpczLm+ip
# Tfe0F1mSQcO3P4bm9sB/RDxGXBda46Q71Wkm1SF94YBnfmKst04uFZrlnCOvWxHq
# calB+Q15OKmhDc+0sdo+mnrHIsV0zd9HCYbE/JElshuW6YUI6N3qdGBuYKVWeg3I
# RFjc5vlIFJ7lv94AvXexmBRyFCTfxxEsHwA/w0sUxmcczB4Go5BfXFSLPuMzW4IP
# xbeGAk5xn+lmRT92MYICWjCCAlYCAQEwgYswdzELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
# dCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5n
# IENBAhB71OWvuswHP6EBIwQiQU0SMAsGCWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIwMDUxNDEwNDAzMlow
# LwYJKoZIhvcNAQkEMSIEIM9FUjIGtPOY2L35ki1/Y3VlGwBxFS/VJu1TgYJSkYiC
# MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMR0znYAfQI5Tg2l5N58FMaA+eKCATz+
# 9lPvXbcf32H4MAsGCSqGSIb3DQEBAQSCAQBLuW+Yq5Yd6Wo2LWYzLAyZ+5PyMao+
# ZDZMmMqMV/OYmm38jqbcpE6wI+/uMiW3N607V3/ikbNZy8qhr+0i9YvD5sMBZf4V
# 4Ox3VI5Z57JcTAv0G71ev7TQRRI9sRKb1ijEiRSdVqL7ZY4G3CMbDx8yTIc5peE3
# 5Nzh8RcDUnRP3qBst2VFNAZFuu+246R/OpkQmzC7cbc5D/IqwhYY92LUZO85TJc6
# 2o6QsPn44IiLIAXSXlLnK2XRRmb5BhaPFvuXoYiEMhVShHKxzZ5pCz58kll1noDT
# ziNKqm+4ZJSzo/Y2EVqCISf+01dptIdTGFP0+jNFecLZEBzIcJ2d2W6m
# SIG # End signature block
