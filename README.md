#CyberArk-Onboard-Single-Account
This will automate the onboarding of an account to CyberArk using AIM and the REST API. 

Requirements
CyberArk EPV v10.1 or later
CyberArk Central Credential Provider
Vaulted Account with access to log in to the PVWA. User must also have the ability to list, add, and manage accounts on the safe.

How To Use
1. Download the ps1 file and place it on a machine or as part of a deployment package.
2. Start the script using ./onboardaccount.ps1 -url "https://mypvwa.mycompany.com" -appid "MyCyberArkApplication" -safe "SafeName" -account "AccountNameToVault" -AcctAddress "where the account resides...mycompany.com or machine name" -PlatformName "PlatformToBeAssigned" -ObjectName "CyberArk Object Name of account used to vault the new credential"
