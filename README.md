
# FileShareUtils
Powershell module to help with all file sharing related tasks **without using WMI !** 

The first functions help to view, list, create, modify and delete shares.  
This also on remote Windows servers or NAS like NetApp.

Also there are functions to view the open sessions and open files on a server

All these functions use netapi32 or advapi32 dll calls.

<br/><br/>
## Functions to work with network shares

#### Get-NetShares [[-Server] \<string>] 

With this command you get a list of all shares on the machine or from a specified server.

The returned array of objects will have the folowing properties:

Property | Description
---------|----------
Server | The machine hosting the shares
Name | The name of the share
Path | The local path shared
Description | The remark or description of the share
CurrentUses | Current connections to this share
Type | The type of the share

<br/>

#### Get-NetFileShares [[-Server] \<string>]

With this command you get a even more detailed list of all the **file** shares on the machine or from a specified server. The IPC and administrative (special) shares are left out.

The returned array of objects will have the folowing properties:

Property | Description
---------|----------
Server | The machine hosting the shares
Name | The name of the share
Path | The local path shared
Description | The remark or description of the share
ABE | Access based enumaration, can be Enabled or Disabled (default)
CachingMode | Offline Folder configuration, can be:<br/>"Manual" (default)<br/>"None" <br/>"Documents" (all documents are automaticaly offline available)<br/>"Programs" ("Performance option", all files are automaticaly offline available)
ShareACLText | Permissions on the share itself. Speical format: Every permission is seperated by a comma and the identity and the access right are seperated by a &#124; _(pipe)_ <br/> If blank probably the default permission "Everyone&#124;FullControl" is set.
CurrentUses | Current connections to this share

<br/>

#### Get-NetShare [-Name] \<string> [[-Server] \<string>] 

With this command you get detailed information about the specified share on the machine or from a remote server.

The returned objects will have the folowing properties:

Property | Description
---------|----------
Server | The machine hosting the share
Name | The name of the share
Path | The local path shared
Description | The remark or description of the share
ABE | Access based enumaration, can be Enabled or Disabled (default)
CachingMode | Offline Folder configuration, can be:<br/>"Manual" (default)<br/>"None" <br/>"Documents" (all documents are automaticaly offline available)<br/>"Programs" ("Performance option", all files are automaticaly offline available)
ShareACLText | Permissions on the share itself. Speical format: Every permission is seperated by a comma and the identity and the access right are seperated by a &#124; _(pipe)_ <br/> If blank probably the default permission "Everyone&#124;FullControl" is set.
CurrentUses | Current connections to this share
ConcurrentUserLimit | Allowed connections to the share. Default is -1 that equals maximum
BranchCache | BranchCache can be Enabled or Disabled (default)
Flags | DEcimal value of the netapi32 1005 structure flags
Type | The type of the share
ShareSDDL | The DACL of the share in SDDL format
ShareACL | The ACL of the share in the standard powershell/.net ACL format. Try to look at the .ShareACL.Access

<br/>

#### New-NetShare [[-Server] \<string>] [-Name] \<string> [-Path] \<string> [[-Description] \<string>] [[-Permissions] \<string>] [[-ABE] \<string>] [[-CachingMode] \<string>] [[-MaxUses] \<int>] 

With this command you create a new share on the machine or on a remote server. The command fails if the share already exists.

The folowing parameters are available:

Property | Description
---------|----------
Server | The machine hosting the share, default is the local machine
**&#42; Name** | The name of the share
**&#42; Path** | The local path to be shared
Description | The remark or description of the share
Permissions | The share permissions to set on the share itself. Speical format: Every permission is seperated by a comma and the identity and the access right are seperated by a &#124; _(pipe)_ <br/>Default: Everyone&#124;FullControl<br/>Possible Permissions: Read, Change, FullControl, Deny-FullControl<br/>Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, \<NETBIOSDOMAINNAME>\\\<sAMAccountName> (domain objects)
ABE | Access based enumaration, can be Enabled or Disabled (default)
CachingMode | Offline Folder configuration, can be:<br/>"Manual" (default)<br/>"None" <br/>"Documents" (all documents are automaticaly offline available)<br/>"Programs" ("Performance option", all files are automaticaly offline available)
MaxUses | Allowed connections to the share. Default is -1 that equals maximum

This function returns nothing.

<br/>

#### Set-NetShare [[-Server] \<string>] [-Name] \<string> [[-Description] \<string>] [[-Permissions] \<string>] [[-ABE] \<string>] [[-CachingMode]\<string>] [[-MaxUses] \<int>]

With this command you modify all changeable options on a share on the machine or on a remote server.

The folowing parameters are available:

Property | Description
---------|----------
Server | The machine hosting the share, default is the local machine
**&#42; Name** | The name of the share
Description | The remark or description of the share
Permissions | The share permissions to set on the share itself. Speical format: Every permission is seperated by a comma and the identity and the access right are seperated by a &#124; _(pipe)_ <br/>Possible Permissions: Read, Change, FullControl, Deny-FullControl<br/>Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, \<NETBIOSDOMAINNAME>\\\<sAMAccountName> (domain objects)
ABE | Access based enumaration, can be Enabled or Disabled (default)
CachingMode | Offline Folder configuration, can be:<br/>"Manual" (default)<br/>"None" <br/>"Documents" (all documents are automaticaly offline available)<br/>"Programs" ("Performance option", all files are automaticaly offline available)
MaxUses | Allowed connections to the share. Default is -1 that equals maximum

This function returns nothing.

<br/>

#### Remove-NetShare [[-Server] \<string>] [-Name] \<string>

With this command deletes a share on the machine or on a remote server.

The folowing parameters 

Property | Description
---------|----------
Server | The machine hosting the share, default is the local machine
**&#42; Name** | The name of the share


This function returns nothing.

<br/>

#### Get-NetSessions [[-Server] \<string>]

With this command you get a detailed and sorted (by user and client) list of all the opened SMB sessions on the machine or on a specified server. 

The returned array of objects will have the folowing properties:

Property | Description
---------|----------
Username | Username used to authenticate
Client | The name (if reverse lookup is possible) or the IP address of the client
Opens | The count of opened objects / files
TimeTS | Session duration in powershell timespan format
Time | Session duration as a string in hours and minutes
Connected | DateTime the session started
IdleTS | Session idle time in powershell timespan format
Idle | Session idle time as a string in hours and minutes
IdleSince | DateTime the session is idle
ConnectionType | This can be empty or showing the SMB version used

<br/>

#### Get-NetOpenFiles [[-Server] \<string>] [[-Path] \<string>] 

With this command you get a sorted (by path and user) list of all over SMB opened files on the machine or on a specified server.  
Be spcifing the left part of the local path the list is filtered to this path and subfolders.

The returned array of objects will have the folowing properties:

Property | Description
---------|----------
Path | Machine local path to the opened file or folder
User | Username used to authenticate
Access | Type of access
Lock | Active locks by this access

<br/><br/>

## Installation

### From the PowerShell Gallery :

The Powershell module is available in the PowerShell Gallery.  
https://www.powershellgallery.com/packages/FileShareUtils

**To install the module from the powershell gallery your computer need to have internet access !**

Install it in PowerShell like this:  
``Install-Module -Name FileShareUtils``

To update the module use -Force :  
``Install-Module FileShareUtils -Force``

Get more informations about the module like this:  
Before installation: ``Save-Module -Name FileShareUtils -Path <path>``

After installation: ``Get-InstalledModule -Name FileShareUtils | FL``  
Look at the code in ISE: 
``Powershell_ISE.exe ((Get-InstalledModule -Name FileShareUtils).InstalledLocation + "\FileShareUtils.psm1")``

### Uninstall module installed from PowerShell Gallery

Use this to uninstall all versions:
``Uninstall-Module FileShareUtils -all``

### Manual installation :

Open your module folder. Probably one of these two:  
``C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\``  
``C:\Program Files\WindowsPowerShell\Modules``  
(Or open a command prompt an enter ``set`` ps to view the env. variable.)

Create a folder named 'FileShareUtils' .  
Oprional: Create a sub folder with a version number if you like.
Copy at least the two files of the module in the created folder:  
* FileShareUtils.psd1
* FileShareUtils.psm1


<br/><br/>

## Credits

I searched very long and intensive for the solutions now built in this module. But I found some helpfull blogs other information on the internet and I like to mention them here.

The first and for me important post is from Alexander from his Kazun PowerShell blog:  
[Managing Access-based enumeration with PowerShell](https://kazunposh.wordpress.com/2011/12/11/%D1%83%D0%BF%D1%80%D0%B0%D0%B2%D0%BB%D0%B5%D0%BD%D0%B8%D0%B5-access-based-enumeration-%D1%81-%D0%BF%D0%BE%D0%BC%D0%BE%D1%89%D1%8C%D1%8E-powershell/)

After testing the code above I found that using netapi32 seams to be the way to go. More search lead me to the blog of Micky Balladelli micky@balladelli.com .  
* [Enumération de shares SMB](https://balladelli.com/enumeration-de-shares-smb/)  
* [Netapi et Powershell](https://balladelli.com/netapi-et-powershell)  
* [Les permissions d’un share](https://balladelli.com/les-permissions-dun-share/)

Most important and cryptic parts to implement the netapi32 and advapi32 functions I borrowed from his code in these 3 blog posts.



