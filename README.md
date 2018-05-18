# FileShareUtils
Powershell module to help with all file server tasks **without using WMI** ! 

The first functions help to view, list, create, modify and delete shares.  
This also on remote Windows servers or NAS like NetApp.

Also there are function to view the open sessions and open files on a server

All these functions use netapi32 or advapi32 dll calls.

## Installation

The Powershell module is available in the PowerShell Gallery.  
https://www.powershellgallery.com/packages/FileShareUtils

Install it in PowerShell like this:

```
Install-Module -Name FileShareUtils
```

Get more informations about the module like this:  
Before download:
```
Save-Module -Name FileShareUtils -Path <path>
```

After installation:
```
Get-InstalledModule -Name FileShareUtils | FL
```
Look at the code in ISE:
```
Powershell_ISE.exe ((Get-InstalledModule -Name FileShareUtils).InstalledLocation + "\FileShareUtils.psm1")
```







