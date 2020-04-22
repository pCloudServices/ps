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

$versionNumber = "7"

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
    
    If($actual -Like '*2016*')
    {
        $result = $true
    }

    elseif($actual -Like '*2012 R2*')
    {
        $errorMsg = "Privileged Cloud installation must be run on Windows Server 2016."   
        $result = $true   
    }
    
    else
    {
        $result = $false
    }

    [PsCustomObject]@{
        expected = "Windows Server 2016";
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
    
    if (((Get-CimInstance CIM_PhysicalMemory).Capacity | Measure-Object -Sum).Sum / (1024 * 1024 * 1024) -ge 8)
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


    $SecPolGPO = @(
      "SeDebugPrivilege",
      "SeBackupPrivilege",
      "SeSecurityPrivilege"
   )
    
    $path = "C:\Windows\Temp\SecReport.txt"
    SecEdit /areas USER_RIGHTS /export /cfg $path

    $SecPol = gc $path

foreach ($sec in $SecPolGPO) {
    $administrators = Select-String $path -Pattern $sec
        if($administrators -eq $null)
            {
        $actual = "False"
        $errorMsg = "Missing administrators in " + $sec
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
        $errorMsg = "Missing administrators in " + $sec
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
"The remote server returned an error: (404) Not Found"
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
    "The remote server returned an error: (404) Not Found"
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

versionUpdate		#check if latest version
GetPublicIP			#retrieve public IP and save it locally

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
		    CheckPrerequisites
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
# MIIfdQYJKoZIhvcNAQcCoIIfZjCCH2ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAOHcLB6TKOuAve
# GgzHXWX5aq6YKu7JMrLy3dcoJfRJmqCCDnUwggROMIIDNqADAgECAg0B7l8Wnf+X
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
# KDHmv37ZRpQvuxAyctrTAPA6HJtuEJnIo6DhFR9LfTGCEFYwghBSAgEBMH4wbjEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExRDBCBgNVBAMT
# O0dsb2JhbFNpZ24gRXh0ZW5kZWQgVmFsaWRhdGlvbiBDb2RlU2lnbmluZyBDQSAt
# IFNIQTI1NiAtIEczAgwhXYQh+9kPSKH6QS4wDQYJYIZIAWUDBAIBBQCgfDAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgVUMNiW70WGAY
# 5PrwYJtJRdUUON9W9cIozHDSvK0zK38wDQYJKoZIhvcNAQEBBQAEggEAh6NSChQb
# 8lDK1B59VLgML/Sq9U9f7NchQmzT0oPxMSqkIJZu2PK9UcPV4+rUF7OdIGvPRDfO
# HuF1iN5OEdQKIvhvQdRKBWXD2r5AtJKqzUXQAs+tIYd2yMu6b0oAu7a6hb/xchev
# SmvV5Gd8AJpGjMNt5jU2j9hZ/RbEQgCTi8asfGlqBwLke94HMeUB4HFn5UDytKCi
# 2BtMxFonUTDJxpgEmtZENMkBUiACwNh5wq+3diG0osXPvEh3le7EP/uYouyS9ZG6
# vpt+29f6n9HYvjJ9Wxd7bSk5FyM3SMkV4B6Ghk6AYMx5hsDtpYIVJVjiMjJlIhHH
# fnJGhrwS0IZRiaGCDiswgg4nBgorBgEEAYI3AwMBMYIOFzCCDhMGCSqGSIb3DQEH
# AqCCDgQwgg4AAgEDMQ0wCwYJYIZIAWUDBAIBMIH+BgsqhkiG9w0BCRABBKCB7gSB
# 6zCB6AIBAQYLYIZIAYb4RQEHFwMwITAJBgUrDgMCGgUABBRFsFcu2UO9pDasYaUF
# GnkeqkTGBAIUT1RDSRj/52KjjfEbVjk9ysZ+fwgYDzIwMjAwNDIyMDkyMzAzWjAD
# AgEeoIGGpIGDMIGAMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNV
# BAMTKFN5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzOgggqL
# MIIFODCCBCCgAwIBAgIQewWx1EloUUT3yYnSnBmdEjANBgkqhkiG9w0BAQsFADCB
# vTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
# ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJp
# U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9W
# ZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAe
# Fw0xNjAxMTIwMDAwMDBaFw0zMTAxMTEyMzU5NTlaMHcxCzAJBgNVBAYTAlVTMR0w
# GwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMg
# VHJ1c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFt
# cGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtZnVlVT52M
# cl0agaLrVfOwAa08cawyjwVrhponADKXak3JZBRLKbvC2Sm5Luxjs+HPPwtWkPhi
# G37rpgfi3n9ebUA41JEG50F8eRzLy60bv9iVkfPw7mz4rZY5Ln/BJ7h4OcWEpe3t
# r4eOzo3HberSmLU6Hx45ncP0mqj0hOHE0XxxxgYptD/kgw0mw3sIPk35CrczSf/K
# O9T1sptL4YiZGvXA6TMU1t/HgNuR7v68kldyd/TNqMz+CfWTN76ViGrF3PSxS9TO
# 6AmRX7WEeTWKeKwZMo8jwTJBG1kOqT6xzPnWK++32OTVHW0ROpL2k8mc40juu1MO
# 1DaXhnjFoTcCAwEAAaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
# CDAGAQH/AgEAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwLgYIKwYBBQUHAQEEIjAgMB4GCCsGAQUFBzABhhJo
# dHRwOi8vcy5zeW1jZC5jb20wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3Muc3lt
# Y2IuY29tL3VuaXZlcnNhbC1yb290LmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMzAdBgNVHQ4E
# FgQUr2PWyqNOhXLgp7xB8ymiOH+AdWIwHwYDVR0jBBgwFoAUtnf6aUhHn1MS1cLq
# BzJ2B9GXBxkwDQYJKoZIhvcNAQELBQADggEBAHXqsC3VNBlcMkX+DuHUT6Z4wW/X
# 6t3cT/OhyIGI96ePFeZAKa3mXfSi2VZkhHEwKt0eYRdmIFYGmBmNXXHy+Je8Cf0c
# kUfJ4uiNA/vMkC/WCmxOM+zWtJPITJBjSDlAIcTd1m6JmDy1mJfoqQa3CcmPU1dB
# kC/hHk1O3MoQeGxCbvC2xfhhXFL1TvZrjfdKer7zzf0D19n2A6gP41P3CnXsxnUu
# qmaFBJm3+AZX4cYO9uiv2uybGB+queM6AL/OipTLAduexzi7D1Kr0eOUA2AKTaD+
# J20UMvw/l0Dhv5mJ2+Q5FL3a5NPD6itas5VYVQR9x5rsIwONhSrS/66pYYEwggVL
# MIIEM6ADAgECAhB71OWvuswHP6EBIwQiQU0SMA0GCSqGSIb3DQEBCwUAMHcxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UE
# CxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQTAeFw0xNzEyMjMwMDAwMDBaFw0yOTAzMjIyMzU5
# NTlaMIGAMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRp
# b24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5
# bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzMwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvDoqq+Ny/aXtUF3FHCb2NPIH4dBV3Z5Cc
# /d5OAp5LdvblNj5l1SQgbTD53R2D6T8nSjNObRaK5I1AjSKqvqcLG9IHtjy1GiQo
# +BtyUT3ICYgmCDr5+kMjdUdwDLNfW48IHXJIV2VNrwI8QPf03TI4kz/lLKbzWSPL
# gN4TTfkQyaoKGGxVYVfR8QIsxLWr8mwj0p8NDxlsrYViaf1OhcGKUjGrW9jJdFLj
# V2wiv1V/b8oGqz9KtyJ2ZezsNvKWlYEmLP27mKoBONOvJUCbCVPwKVeFWF7qhUhB
# IYfl3rTTJrJ7QFNYeY5SMQZNlANFxM48A+y3API6IsW0b+XvsIqbAgMBAAGjggHH
# MIIBwzAMBgNVHRMBAf8EAjAAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAj
# BggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIw
# GRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwQAYDVR0fBDkwNzA1oDOgMYYvaHR0
# cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jcmwwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMHcGCCsGAQUFBwEB
# BGswaTAqBggrBgEFBQcwAYYeaHR0cDovL3RzLW9jc3Aud3Muc3ltYW50ZWMuY29t
# MDsGCCsGAQUFBzAChi9odHRwOi8vdHMtYWlhLndzLnN5bWFudGVjLmNvbS9zaGEy
# NTYtdHNzLWNhLmNlcjAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1w
# LTIwNDgtNjAdBgNVHQ4EFgQUpRMBqZ+FzBtuFh5fOzGqeTYAex0wHwYDVR0jBBgw
# FoAUr2PWyqNOhXLgp7xB8ymiOH+AdWIwDQYJKoZIhvcNAQELBQADggEBAEaer/C4
# ol+imUjPqCdLIc2yuaZycGMv41UpezlGTud+ZQZYi7xXipINCNgQujYk+gp7+zvT
# Yr9KlBXmgtuKVG3/KP5nz3E/5jMJ2aJZEPQeSv5lzN7Ua+NSKXUASiulzMub6KlN
# 97QXWZJBw7c/hub2wH9EPEZcF1rjpDvVaSbVIX3hgGd+Yqy3Ti4VmuWcI69bEepx
# qUH5DXk4qaENz7Sx2j6aescixXTN30cJhsT8kSWyG5bphQjo3ep0YG5gpVZ6DchE
# WNzm+UgUnuW/3gC9d7GYFHIUJN/HESwfAD/DSxTGZxzMHgajkF9cVIs+4zNbgg/F
# t4YCTnGf6WZFP3YxggJaMIICVgIBATCBizB3MQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0
# IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0ECEHvU5a+6zAc/oQEjBCJBTRIwCwYJYIZIAWUDBAIBoIGkMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjAwNDIyMDkyMzAzWjAv
# BgkqhkiG9w0BCQQxIgQglsT/oaMnTnCsk5R04smt0wdWi0WW8qixlyGFlpksVc4w
# NwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgxHTOdgB9AjlODaXk3nwUxoD54oIBPP72
# U+9dtx/fYfgwCwYJKoZIhvcNAQEBBIIBAD21wj0flS9Lvywnlqn5wAVE4/Y7shET
# 6IvO1kbhI7yxcYJBBVD77WjL3+LoyYEf0YRv3repfI0Ld/PTYSvVKKxbBQI8ax6s
# qeaGEB3dNPqDBugM6RhpwTFZw4ElKagw+8RHs46jhUmc2JUA5cPnnuHacN5fJO1Y
# 130I7j3llyWTTc8RIUFikkJsun9N0H0npsbSiFmHFwvhoFAKwll4Q4ISvqkSPbga
# Gh1tT6rXJHke33ZvEkdnHqTjUBPd4J3rkBk5bGdpzVUppjXJ6yINxxPiGRHZoBDj
# HkJM+238YYG2PuOAauDKMNADvp5+gzYgUa2IDaveJp2jVcO+GpuVOxU=
# SIG # End signature block
