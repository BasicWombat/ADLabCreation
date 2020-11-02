<# --------------------------------------------------------------------------
                     Lab AD Setup Script
                   Date: 20-May-2018
                 Created by: Daniel Burrowes
# --------------------------------------------------------------------------#>

# -Verbose and -Debug

[CmdletBinding()]
param()

# --------------------------------------------------------------------------

Import-Module ActiveDirectory


# Create New OUs

$domain = "DC=Company,DC=Local"
$companyOU = "OU=Company,DC=Company,DC=Local"
$arrayOU = @("Users","Service Accounts","Security Groups","Computers","Servers","Citrix Servers","Workstations")

Write-host "Setting up OUs..."

New-ADOrganizationalUnit -Name "Company" -Path $domain -PassThru
foreach ($ou in $arrayOU) {New-ADOrganizationalUnit -Name $ou -Path $companyOU -PassThru}

#Create New Users

Write-Host "Creating new users..."

$username = "daniel.burrowes"

New-ADUser -Name "Daniel Burrowes" -GivenName Daniel -Surname Burrowes `
-SamAccountName $username `
-UserPrincipalName daniel.burrowes@company.local `
-AccountPassword (Read-Host -AsSecureString "Account Password:") `
-path "OU=Users,OU=Company,DC=Company,DC=Local" `
-PassThru | Enable-ADAccount

# Create New Group

$secGroupLocation = "OU=Security Groups,OU=Company,DC=Company,DC=Local"
$arraySecGroups = @(“Citrix Users Group”,“Company Share Group”)

Write-Host "Creating Groups..."

foreach ($secGroup in $arraySecGroups) {New-ADGroup -Name $secGroup -GroupCategory Security -GroupScope Global –path $secGroupLocation}

Write-Host "Adding Members to new groups..."

foreach ($secGroup in $arraySecGroups) {Add-ADGroupMember -Identity $secGroup -Members $username}

#Create Shared Drive

$ShareDir = "C:\SharedFolders\Company" 
Write-Host "Creating Folder $ShareDir"
New-Item -Path $ShareDir -ItemType directory -Force

$Acl = Get-Acl $ShareDir
$permission = “Company Share Group”,"FullControl","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$Acl.SetAccessRule($accessRule)
$Acl | Set-Acl -Path $ShareDir

if(!(Get-SMBShare -Name ShareName -ea 0)){
New-SMBShare –Name “Shared” –Path $ShareDir -ChangeAccess "Users" -FullAccess "Administrators"}

Write-Host "Done!"
Pause 