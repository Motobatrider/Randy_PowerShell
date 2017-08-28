# PSADHandler.ps1
# By Randy
# 21 Aug 2017
# For handling AD issue e.g. reset password, move OU, find bitlocker ID, and others
# Define fuctions
# functions:
# -------------------------------------------------## ##-------------------------------------------------------------------------
# Find user information: PSAD_UserInfo($username)
# Reset passwqord: PSAD_RestPW ($username,$password)
# Reset Admin password: PSAD_RestADMPW ($username,$password)
#
#
#
#
#
#
#
#
#


# Run As admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }


# Import AD module
import-module activedirectory

# Find user information
# Get 
Function PSAD_UserInfo ($username)
{
    Get-ADUser -LDAPFilter "(DisplayName=$username)" -Properties "CanonicalName","Country","City","Company","Department","departmentNumber","Description","EmployeeID","extensionAttribute6","Manager","mobile","OfficePhone","Title","whenChanged","DisplayName"
}

# Reset password
Function PSAD_RestPW ($username,$password)
{
    $Disname = PSAD_GetSAccount($username)
    $AccountPassword2 = ConvertTo-SecureString -String $password -AsPlainText -Force
    set-adaccountpassword $Disname -NewPassword $AccountPassword2 -Reset -PassThru
    Write-Host "Password Reset OK!"
}

# Reset Adm password
Function PSAD_RestADMPW ($username,$password)
{
    $AccountPassword2 = ConvertTo-SecureString -String $password -AsPlainText -Force
    set-adaccountpassword $username -NewPassword $AccountPassword2 -Reset -PassThru
    Write-Host "Password Reset OK!"
}

# Find bitlocker password
Function PSAD_BLK ($Computername)
{
    $computer = Get-ADComputer -Filter {name -eq $Computername}
    $BitLockerObjects = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $computer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
    foreach ($id in $BitLockerObjects) 
    {
        $id.distinguishedname; 
        $id.'msFve-recoverypassword'
    }
}
# Move user

# Unlock user
Function PSAD_UnlockAD ($username)
{
    $Disname = PSAD_GetSAccount($username)
    Unlock-ADAccount -Identity $Disname 
}

# Get Samaccount
Function PSAD_GetSAccount ($username)
{
    $Disname = Get-ADUser -LDAPFilter "(DisplayName=$username)" | Select DistinguishedName
    return $Disname
}


#Run Test
