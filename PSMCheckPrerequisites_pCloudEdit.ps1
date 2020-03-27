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

$versionNumber = "6"

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
    }
    
    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = ""
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
$webVersion = New-Object System.Net.WebClient

Try
{
$checkVersion = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/sn1kzZe/ps/master/Latest.txt" -ErrorAction SilentlyContinue).Content.toString()
}
Catch
{
"The remote server returned an error: (404) Not Found"
}


if ($checkVersion -gt $versionNumber){
Write-Host "Found new version: $checkVersion, Updating..." -ForegroundColor DarkCyan
Try
{
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/sn1kzZe/ps/master/PSMCheckPrerequisites_pCloudEdit.ps1" -ErrorAction SilentlyContinue -OutFile "$PSCommandPath.NEW"
}
Catch
{
"The remote server returned an error: (404) Not Found"
}

        if (Test-Path -Path $PSCommandPath$checkVersion){
        Rename-Item -path $PSCommandPath -NewName "$PSCommandPath.OLD"
        Rename-Item -Path "$PSCommandPath.NEW" -NewName $PSCommandPath
        Write-Host "Finished Updating, please restart script"
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
	

	
###########################################################################################
# Main start
###########################################################################################

versionUpdate #check if latest version

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
