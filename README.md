# MSOLSpray
A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.

BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS!

## Why another fork?.. Enumerate and output valid usernames to a file!
This modification allows MSOLSpray to now be used for identifying valid usernames collected during the reconnaissance phase. The -Enum flag is optional and can be used to validate usernames and output valid ones to a file.

Simply use the '-Enum' option and once the tool completes its execution, the tool will print "Valid users saved to Valid-Usernames.txt" and the file 'Valid-Usernames.txt' will appear in the same location where you ran this tool.

You will need a userlist file with target email addresses one per line within a PowerShell terminal and a single password used for the password spray.

```PowerShell
import-module .\MSOLSpray.ps1
Invoke-MSOLSpray -Enum -UserList .\userlist.txt -Password ILoveBatman
```

The '-Enum' option adds users to the Valid-Usernames.txt file that meet any one of the following criteria: 
  - Valid Credentials
  - Invalid Password but Valid Username
  - Valid Credentials but MFA in use
  - Locked Accounts
  - Account with Expired Passwords

Modifications to original script are marked with '#Enum' - PAN1K
