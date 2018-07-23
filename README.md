# CyberArk-Onboard-Single-Account
This will automate the onboarding of an account to CyberArk using AIM and the REST API. 

## Requirements

1. CyberArk EPV v10.1 or later
2. CyberArk Central Credential Provider
3. Vaulted Account with access to log in to the PVWA. User must also have the ability to list, add, and manage accounts on the safe.

## How To Use

1. Download the ps1 file and place it on a machine or as part of a deployment package.
2. Start the script using ./onboardaccount.ps1 -url "https://mypvwa.mycompany.com" -appid "MyCyberArkApplication" -safe "SafeName" -account       "AccountNameToVault" -AcctAddress "where the account resides...mycompany.com or machine name" -PlatformName "PlatformToBeAssigned" -ObjectName "CyberArk Object Name of account used to vault the new credential"

## Certificate Authentication

1. This script supports Certificate Authentication. Pass the object name of your certificate ("CN=MyComputer") if certificate authentication is configured    in your vault. For instructions, see the CyberArk CCP guide.
2. It's suggested that you place the certificate in the user store of the account that will execute the script.