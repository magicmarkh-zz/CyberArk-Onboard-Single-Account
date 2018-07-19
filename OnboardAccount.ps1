###########################################################################
#
# NAME: Single Account Onboard Utility
#
# AUTHOR:  Mark Hurter - Framework shamelessly stolen from Assaf Miron
#
# COMMENT: 
# This script will retreive credentials to login using the API to vault and immediately reconcile an account
# If an account already exists in the vault, it will automatically be reconciled
#
# VERSION HISTORY:
# 1.0 7/18/2018 - Initial release
#
###########################################################################
[CmdletBinding(DefaultParametersetName="Create")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$true,HelpMessage="Please enter the Vault application name")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[String]$AppID,
	
	[Parameter(Mandatory=$true,HelpMessage="Please enter Safe Name")]
	[String]$Safe,

	[Parameter(Mandatory=$true,HelpMessage="Please enter Account Name to vault")]
	[Alias("account")]
	[String]$AcctToVault,

    [Parameter(Mandatory=$true,HelpMessage="Please enter Address for Account to vault")]
	[String]$AcctAddress,

	[Parameter(Mandatory=$true,HelpMessage="Please enter Platform Name for account to vault")]
	[String]$PlatformName,
	
	[Parameter(Mandatory=$true,HelpMessage="Please enter Object Name of API user")]
	[String]$ObjectName,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\Account_Onboarding_Utility.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/PasswordVault/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_CyberArkAuthentication = $URL_PVWAWebServices+"/auth/Cyberark/CyberArkAuthenticationService.svc"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/Logon"
$URL_CyberArkLogoff = $URL_CyberArkAuthentication+"/Logoff"
$URL_AIM = $PVWAURL+ "/aimwebservice/v1.1/aim.asmx?WSDL"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SafeDetails = $URL_PVWABaseAPI+"/Safes/{0}"
$URL_SafeMembers = $URL_PVWABaseAPI+"/Safes/{0}/Members"
$URL_Account = $URL_PVWABaseAPI+"/Account"
$URL_Accounts = $URL_PVWABaseAPI+"/Accounts"
$URL_AccountDetails = $URL_Accounts+"/{0}"
$URL_V10API = $PVWAURL+"/PasswordVault/api"


#region CSV Path (not used)
# Script Defaults - section not needed - we are not importing from CSV
# ---------------
#$g_CsvDefaultPath = $Env:CSIDL_DEFAULT_DOWNLOADS
#endregion

# Safe Defaults
# --------------
$CPM_NAME = "PasswordManager"
$NumberOfDaysRetention = 7
$NumberOfVersionsRetention = 0

# Template Safe parameters
# ------------------------
$TemplateSafeDetails = ""
$TemplateSafeMembers = ""

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ""

#region Functions
Function Test-CommandExists
{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

Function Encode-URL($sText)
{
	if ($sText.Trim() -ne "")
	{
		Write-Debug "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return $sText
	}
}

Function Log-MSG
{
<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
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
		[Parameter(Mandatory=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose")]
		[String]$type = "Info"
	)
	
	If ($Header) {
		"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
		Write-Host "======================================="
	}
	ElseIf($SubHeader) { 
		"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
		Write-Host "------------------------------------"
	}
	
	$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
	$writeToFile = $true
	# Replace empty message with 'N/A'
	if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
	# Check the message type
	switch ($type)
	{
		"Info" { 
			Write-Host $MSG.ToString()
			$msgToWrite += "[INFO]`t$Msg"
		}
		"Warning" {
			Write-Host $MSG.ToString() -ForegroundColor DarkYellow
			$msgToWrite += "[WARNING]`t$Msg"
		}
		"Error" {
			Write-Host $MSG.ToString() -ForegroundColor Red
			$msgToWrite += "[ERROR]`t$Msg"
		}
		"Debug" { 
			if($InDebug)
			{
				Write-Debug $MSG
				$msgToWrite += "[DEBUG]`t$Msg"
			}
			else { $writeToFile = $False }
		}
		"Verbose" { 
			if($InVerbose)
			{
				Write-Verbose $MSG
				$msgToWrite += "[VERBOSE]`t$Msg"
			}
			else { $writeToFile = $False }
		}
	}
	
	If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
	If ($Footer) { 
		"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
		Write-Host "======================================="
	}
}

#region opens file dialog for CSV import (not used)
Function OpenFile-Dialog($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}
#endregion

Function Invoke-Rest
{
	param ($Command, $URI, $Header, $Body, $ErrorAction="Continue")
	
	$restResponse = ""
	try{
		Log-Msg -Type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
        $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
	} catch {
		If($_.Exception.Response.StatusDescription -ne $null)
		{
			Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
		}
		else
		{
			Log-Msg -Type Error -Msg "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Log-Msg -Type Verbose -MSG $restResponse
	return $restResponse
}

Function Get-Safe
{
	param ($safeName)
	$_safe = $null
	try{
		$accSafeURL = $URL_SafeDetails -f $safeName
		$_safe = $(Invoke-Rest -Uri $accSafeURL -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_safe.GetSafeResult
}

Function Get-SafeMembers
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
	$_safeMembers = $null
	$_safeOwners = $null
	try{
		$accSafeMembersURL = $URL_SafeMembers -f $safeName
		$_safeMembers = $(Invoke-Rest -Uri $accSafeMembersURL -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
		$_safeOwners = $_safeMembers.members | Select-Object -Property @{Name = 'MemberName'; Expression = {$_.UserName}}, Permissions
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_safeOwners
}

Function Test-Safe
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
		
	try{
		If ($null -eq $(Get-Safe -safeName $safeName))
		{
			# Safe does not exist
			Log-Msg -Type Warning -MSG "Safe $safeName does not exist"
			return $false
		}
		else
		{
			# Safe exists
			Log-Msg -Type Info -MSG "Safe $safeName exists"
			return $true
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception
	}
}

Function Get-Account
{
	param ($accountName, $accountAddress, $safeName)
	$_account = $null
	try{
		# Search for created account
		$urlSearchAccount = $URL_Accounts+"?Safe="+$(Encode-URL $safeName)+"&Keywords="+$(Encode-URL "$accountName $accountAddress")
		$_account = $(Invoke-Rest -Uri $urlSearchAccount -Header $g_LogonHeader -Command "Get")
		if($null -ne $_account)
		{
			$_account = $_account.accounts
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_account
}

Function Test-Account
{
	param ($accountName, $accountAddress, $safeName)
	try{
		If ($null -eq $(Get-Account -accountName $accountName -accountAddress $accountAddress -safeName $safeName))
		{
			# No accounts found
			Log-Msg -Type Debug -MSG "Account $accountName does not exist"
			return $false
		}
		else
		{
			# Account Exists
			Log-Msg -Type Info -MSG "Account $accountName exist"
			return $true
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception
	}
}

Function Reconcile-Account
{
    param($accountId)
    try{
    	    $restBody = "{}"
            $reconcile_url = "$($URL_V10API)/Accounts/$($accountId)/Reconcile"
            $reconcileAccountResult = $(Invoke-Rest -Uri $reconcile_url -Header $g_LogonHeader -Body $restBody -Command "Post")
            if($reconcileAccountResult -ne $null)
	        {
		        Log-Msg -Type Info -MSG "Reconciled $($AcctToVault)@$($AcctAddress) successfully"
	        }
    }
    catch{
		Log-Msg -Type Error -MSG $_.Exception
    }
}

Function Get-LogonHeader
{
	param($User, $Password)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$User;password=$Password } | ConvertTo-Json
	try{
	    # Logon
	    $logonResult = Invoke-RestMethod -Uri $URL_CyberArkLogon -Method "Post" -ContentType "application/json" -Body $logonBody
	    # Save the Logon Result - The Logon Token
	    $logonToken = $logonResult.CyberArkLogonResult
		Log-Msg -Type Debug -MSG "Got logon token: $logonToken"
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ([string]::IsNullOrEmpty($logonToken))
    {
        Log-Msg -Type Error -MSG "Logon Token is Empty - Cannot login"
        exit
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}


#endregion

# Check if to disable SSL verification
If($DisableSSLVerify)
{
	try{
		#Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Sevrer needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Log-Msg -Type Error -MSG "Could not change SSL validation"
		Log-Msg -Type Error -MSG $_.Exception
		exit
	}
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false)
{
   Log-Msg -Type Error -MSG  "This script requires Powershell version 3 or above"
   exit
}	

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL))
{
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
	
	try{
		# Validate PVWA URL is OK
		Log-Msg -Type Debug -MSG  "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	} catch [System.Net.WebException] {
		If(![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__))
		{
			Log-Msg -Type Error -MSG $_.Exception.Response.StatusCode.Value__
		}
	}
	catch {		
		Log-Msg -Type Error -MSG "PVWA URL could not be validated"
		Log-Msg -Type Error -MSG $_.Exception
	}
	
}
else
{
	Log-Msg -Type Error -MSG "PVWA URL can not be empty"
	exit
}

# Header
#Log-Msg -Type Info -MSG "Welcome to Accounts Onboard Utility" -Header
#Log-Msg -Type Info -MSG "Getting PVWA Credentials to start Onboarding Accounts" -SubHeader


#region [Logon]
	# Get Credentials to Login
	# ------------------------

	$proxy = New-WebServiceProxy -Uri $URL_AIM
    $t = $proxy.getType().namespace
    $request = New-Object ($t + ".passwordRequest")
    $request.AppID = $AppID;
    $request.Query = "Safe="+$Safe+";Folder=Root;Object="+$ObjectName
    $response = $proxy.GetPassword($request)

	$g_LogonHeader = $(Get-LogonHeader -User $response.UserName -Password $response.Content)
#endregion

#check to see if the account already exists
		
$accExists = $(Test-Account -safeName $Safe -accountName $AcctToVault -accountAddress $accountAddress)

try{
    If ($accExists -eq $false)
    {

	    # Create the Account
        $tmp_pw="1234"
        $restBody = @{account=@{username=$AcctToVault;address=$AcctAddress;safe=$Safe;platformID=$PlatformName;password=$tmp_pw }}| ConvertTo-Json -Depth 5
        Log-Msg -Type Debug -Msg $restBody
	    $addAccountResult = $(Invoke-Rest -Uri $URL_Account -Header $g_LogonHeader -Body $restBody -Command "Post")
	    if($addAccountResult -ne $null)
	    {
		    Log-Msg -Type Info -MSG "Onboarded $($AcctToVault)@$($AcctAddress) successfully"

            #now reconcile the password so that it's no longer known
            $n_acct = (Get-Account -accountName $AcctToVault -accountAddress $AcctAddress -safeName $Safe)
            Reconcile-Account -accountId $n_acct.Accountid
	    }
    }
    Else
    {
        #trigger an account reconcile
        $n_acct = (Get-Account -accountName $AcctToVault -accountAddress $AcctAddress -safeName $Safe)
	    Reconcile-Account -accountId $n_acct.AccountId
        #write Log Msg
    }
}
catch{
	Log-Msg -Type Error -MSG "There was an error onboarding $($account.username)@$($account.address) into the Password Vault."
}


#region [Logoff]
	# Logoff the session
    # ------------------
    Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
	# Footer

#endregion