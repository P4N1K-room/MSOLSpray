# MSOLSpray
A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.

BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

## Why another fork?.. Enumerate and output valid usernames to a file!
This modification allows MSOLSpray to now be used for identifying valid usernames collected during the reconnaissance phase. The -Enum flag is optional and can be used to validate usernames and output valid ones to a file.

Simply use the '-Enum' option and once the tool completes its execution, the tool will print "Valid users saved to Valid-Usernames.txt" and the file 'Valid-Usernames.txt' will appear in the same location where you ran this tool.

You will need a userlist file with target email addresses one per line within a PowerShell terminal and a single password used for the password spray.

```PowerShell
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -Enum -UserList .\userlist.txt -Password ILoveBatman
```

The '-Enum' option adds users to the Valid-Usernames.txt file that meet any one of the following criteria: 
  - Valid Credentials
  - Invalid Password but Valid Username
  - Valid Credentials but MFA in use
  - Locked Accounts
  - Account with Expired Passwords

Modifications to original script are marked with '#Enum' - PAN1K

## Why another spraying tool?
Yes, I realize there are other password spraying tools for O365/Azure. The main difference with this one is that this tool not only is looking for valid passwords, but also the extremely verbose information Azure AD error codes give you. These error codes provide information relating to if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, if the account is disabled, if the password is expired and much more.

So this doubles, as not only a password spraying tool but also a Microsoft Online recon tool that will provide account/domain enumeration. In limited testing it appears that on valid login to the Microsoft Online OAuth2 endpoint it isn't auto-triggering MFA texts/push notifications making this really useful for finding valid creds without alerting the target.

Lastly, this tool works well with [FireProx](https://github.com/ustayready/fireprox) to rotate source IP addresses on authentication requests. In testing this appeared to avoid getting blocked by Azure Smart Lockout.

## Quick Start
You will need a userlist file with target email addresses one per line. Open a PowerShell terminal from the Windows command line with 'powershell.exe -exec bypass'.

```PowerShell
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
```

### Invoke-MSOLSpray Options
```
UserList  - UserList file filled with usernames one-per-line in the format "user@domain.com"
Password  - A single password that will be used to perform the password spray.
Enum      - Optional flag to enumerate and output valid usernames to a file.
OutFile   - A file to output valid results to.
Force     - Forces the spray to continue and not stop when multiple account lockouts are detected.
URL       - The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
```
