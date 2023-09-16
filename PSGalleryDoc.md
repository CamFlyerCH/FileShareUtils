
# FileShareUtils
Powershell module to help with all file sharing related tasks **without using WMI !** 

The first functions help to view, list, create, modify and delete shares.  
This also on remote Windows servers or NAS like NetApp.

Also there are functions to view the open sessions and open files on a server.

Also there ae functions to list available snapshots and seek for folders and files (versions) in snapshots.

All these functions use netapi32 or advapi32 dll calls.



Please check also the better documented GitHub page https://github.com/CamFlyerCH/FileShareUtils !   




<br/><br/>
## Functions to work with network shares

#### Get-NetShares [[-Server] \<string>]  [[-Level] \<Int>]

With this command you get a list of all shares on the machine or from a specified server. I you do not have admin rights you can try the option -Level 1  (Default is 502).


<br/>

#### Get-NetFileShares [[-Server] \<string>]

With this command you get a even more detailed list of all the **file** shares on the machine or from a specified server. The IPC and administrative (special) shares are left out.

<br/>

#### Get-NetShare [-Name] \<string> [[-Server] \<string>] 

With this command you get detailed information about the specified share on the machine or from a remote server.

<br/>

#### New-NetShare [[-Server] \<string>] [-Name] \<string> [-Path] \<string> [[-Description] \<string>] [[-Permissions] \<string>] [[-ABE] \<string>] [[-CachingMode] \<string>] [[-MaxUses] \<int>] 

With this command you create a new share on the machine or on a remote server. The command fails if the share already exists.

<br/>

#### Redo-NetShare [[-Server] \<string>] [-Name] \<string> [-Path] \<string> [[-Description] \<string>] [[-Permissions] \<string>] [[-ABE] \<string>] [[-CachingMode] \<string>] [[-MaxUses] \<int>] 

With this command you create a new share on the machine or on a remote server. If the share already exists, the share will be modified with the given options. If the path changes, the share will be deleted and recreated while preserving the options from the deleted share.

<br/>

#### Set-NetShare [[-Server] \<string>] [-Name] \<string> [[-Description] \<string>] [[-Permissions] \<string>] [[-ABE] \<string>] [[-CachingMode]\<string>] [[-MaxUses] \<int>]

With this command you modify all changeable options on a share on the machine or on a remote server.

<br/>

#### Remove-NetShare [[-Server] \<string>] [-Name] \<string>

With this command deletes a share on the machine or on a remote server.

<br/>

#### Get-NetShareDiskSpace [-Name] \<string> [[-Server] \<string>] [[-Unit] \<string>] 

With this command you retrieve the available space for the calling user and the total free space on the disk and the total disk space of the specified share on the machine or from a remote server.
The returned values are in UInt64. Default these are bytes, but with the Unit option you can get rounded values in KB, MB, GB or TB.

<br/>

#### Get-NetSessions [[-Server] \<string>]  [[-Level] \<Int>]

With this command you get a detailed and sorted (by user and client) list of all the opened SMB sessions on the machine or on a specified server.
For NAS that return an error "The system call level is not correct" try the option -Level 1.

<br/>

#### Close-NetSession [[-Server] \<string>] [-User] \<string> [-ClientIP] \<string>

Closes an open session on a local or remote computer by user AND client IP.

<br/>

#### Get-NetOpenFiles [[-Server] \<string>] [[-Path] \<string>] -WithID \<switch>

With this command you get a sorted (by path and user) list of all over SMB opened files on the machine or on a specified server.  
By specifying the left part of the local path the list is filtered to this path and subfolders.
By adding the option -WithID the returned values contain also a FileID that can be used to use Close-NetOpenFiles

<br/>

#### Close-NetOpenFiles [[-Server] \<string>] [-FileID] \<int>

Closes an open file or folder from a local or remote computer.

<br/>

#### Get-SnapshotPath [[-Path] \<string>]

With this command will return you every snapshot (path) for a given folder (on a network share).

<br/>

#### Get-SnapshotItems [[-Path] \<string>]

With this command will return file or folder objects found existing in snapshots for a given full path to a folder or file.
The folder/file does not need to exist at the present location. For folders every existing snapshot is listed. 
For files only older versions are returned.

The returned array of objects will be of the type DirectoryInfo or FileInfo
with the additional property SnapshotCreationTime (in DateTime format).

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

Get more information about the module like this:  
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
Optional: Create a sub folder with a version number if you like.
Copy at least the two files of the module in the created folder:  
* FileShareUtils.psd1
* FileShareUtils.psm1


<br/><br/>

## Credits

I searched very long and intensive for the solutions now built in this module. But I found some helpful blogs other information on the internet and I like to mention them here.

The first and for me important post is from Alexander from his Kazun PowerShell blog:  
[Managing Access-based enumeration with PowerShell](https://kazunposh.wordpress.com/2011/12/11/%D1%83%D0%BF%D1%80%D0%B0%D0%B2%D0%BB%D0%B5%D0%BD%D0%B8%D0%B5-access-based-enumeration-%D1%81-%D0%BF%D0%BE%D0%BC%D0%BE%D1%89%D1%8C%D1%8E-powershell/)

After testing the code above I found that using netapi32 seams to be the way to go. More search lead me to the blog of Micky Balladelli micky@balladelli.com .  
[Enumération de shares SMB](https://balladelli.com/enumeration-de-shares-smb/)  
[Netapi et Powershell](https://balladelli.com/netapi-et-powershell)  
 [Les permissions d’un share](https://balladelli.com/les-permissions-dun-share/)

Most important and cryptic parts to implement the netapi32 and advapi32 functions I borrowed from his code in these 3 blog posts.

A long time I was looking into implementing functions to enumerate snapshots / previous versions. Many attemts to implement this in Powershell failed while I only found working C++ and C# examples from these repos :
https://github.com/HiraokaHyperTools/EnumerateSnapshots
https://github.com/HiraokaHyperTools/LibEnumRemotePreviousVersion

Then I found this [Get-SnapshotPath](https://gist.github.com/jborean93/f60da33b08f8e1d5e0ef545b0a4698a0) Gist from Jordan Borean (@jborean93) <jborean93@gmail.com> that then finaly helped me to add the functions I wanted.