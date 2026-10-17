<#
    .SYNOPSIS
        Shows which share information an account can read from a server

    .DESCRIPTION
        The access check for share information happens on the server (srvsvc on Windows,
        Samba on most NAS), not in the API on the client. This script asks the server for
        every information level and reports per level whether it works for the account
        that runs the script.

        Tested calls:
          - NetShareGetInfo  levels 0, 1, 2, 501, 502, 503, 1005
          - NetShareEnum     levels 0, 1, 2, 501, 502, 503
          - GetFileInformationByHandleEx(FileRemoteProtocolInfo) on \\Server\Share\
          - Experimental: open \\Server\Share\ with MAXIMUM_ALLOWED and read the granted access

        To test another account without logging off, start the script with runas /netonly.
        The local session stays yours, but all network access uses the other account:

          runas /netonly /user:DOMAIN\User "pwsh.exe -ExecutionPolicy Bypass -File C:\Path\Test-NetShareInfoLevels.ps1 -Server srv01 -Share Data"

    .PARAMETER Server
        Name of the server (NetBIOS name, DNS name or IP address)

    .PARAMETER Share
        Name of the share to test

    .PARAMETER OutFile
        Optional path of a text file that receives a copy of the output (transcript)

    .PARAMETER NoPause
        Do not wait for Enter at the end

    .NOTES
        Name: Test-NetShareInfoLevels
        Author: Jean-Marc Ulrich
        Part of https://github.com/CamFlyerCH/FileShareUtils, background in issues #6 and #13
        Version History:
            1.0 //First version 17.10.2026

    .EXAMPLE
        .\Test-NetShareInfoLevels.ps1 -Server 'srv1234' -Share 'Data'

        Description
        -----------
        Tests all information levels for the share Data on srv1234 with the current account
#>
[CmdletBinding()]
Param (
    [Parameter(Position=0,Mandatory=$True)]
    [string]$Server,

    [Parameter(Position=1,Mandatory=$True)]
    [string]$Share,

    [Parameter(Mandatory=$False)]
    [string]$OutFile,

    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'
$Server = $Server.TrimStart('\')
$ScriptErrors = New-Object System.Collections.Generic.List[string]
$Results = New-Object System.Collections.Generic.List[object]
$Activity = "Testing share information for \\$Server\$Share"

Try { $Host.UI.RawUI.WindowTitle = "Test-NetShareInfoLevels - \\$Server\$Share" } Catch { }

If ($OutFile) {
    Try { Start-Transcript -Path $OutFile -Force | Out-Null } Catch { $ScriptErrors.Add("Transcript could not be started: $($_.Exception.Message)") }
}

# Native calls ===================================================================================

$NativeCode = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileShareUtilsTest
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_0
    {
        public string Name;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1
    {
        public string Name;
        public uint Type;
        public string Remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_2
    {
        public string Name;
        public uint Type;
        public string Remark;
        public uint Permissions;
        public uint MaxUses;
        public uint CurrentUses;
        public string Path;
        public string Password;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_501
    {
        public string Name;
        public uint Type;
        public string Remark;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_502
    {
        public string Name;
        public uint Type;
        public string Remark;
        public uint Permissions;
        public uint MaxUses;
        public uint CurrentUses;
        public string Path;
        public string Password;
        public uint Reserved;
        public IntPtr SecurityDescriptor;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_503
    {
        public string Name;
        public uint Type;
        public string Remark;
        public uint Permissions;
        public uint MaxUses;
        public uint CurrentUses;
        public string Path;
        public string Password;
        public string ServerName;
        public uint Reserved;
        public IntPtr SecurityDescriptor;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SHARE_INFO_1005
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    public static class Native
    {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetShareGetInfo(string servername, string netname, int level, out IntPtr bufptr);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetShareEnum(string servername, int level, out IntPtr bufptr, int prefmaxlen,
            out int entriesread, out int totalentries, ref int resume_handle);

        [DllImport("netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr securityDescriptor,
            uint requestedRevision, uint securityInformation, out IntPtr stringSecurityDescriptor, out uint length);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass,
            IntPtr fileInformation, uint bufferSize);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationFile(SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock,
            out uint fileInformation, uint length, int fileInformationClass);

        [DllImport("ntdll.dll")]
        public static extern int RtlNtStatusToDosError(int status);

        // DACL of a security descriptor as SDDL string, error code in 'error'
        public static string SdToSddl(IntPtr securityDescriptor, out int error)
        {
            IntPtr sddlPtr;
            uint length;
            // SDDL_REVISION_1 = 1, DACL_SECURITY_INFORMATION = 4
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(securityDescriptor, 1, 4, out sddlPtr, out length))
            {
                error = Marshal.GetLastWin32Error();
                return null;
            }
            error = 0;
            string sddl = Marshal.PtrToStringUni(sddlPtr);
            LocalFree(sddlPtr);
            return sddl;
        }

        // Opens a directory (share root) with the given access, error code in 'error'
        public static SafeFileHandle OpenDirectory(string path, uint desiredAccess, out int error)
        {
            // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE = 7, OPEN_EXISTING = 3,
            // FILE_FLAG_BACKUP_SEMANTICS = 0x02000000 (needed to open a directory)
            SafeFileHandle handle = CreateFileW(path, desiredAccess, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
            error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
            return handle;
        }

        // FileRemoteProtocolInfo = 13, returns 0 or the Win32 error code
        public static int QueryRemoteProtocolInfo(SafeFileHandle handle, IntPtr buffer, uint size)
        {
            if (GetFileInformationByHandleEx(handle, 13, buffer, size)) { return 0; }
            return Marshal.GetLastWin32Error();
        }

        // FileAccessInformation = 8, returns the NTSTATUS
        public static int QueryGrantedAccess(SafeFileHandle handle, out uint grantedAccess)
        {
            IO_STATUS_BLOCK ioStatus;
            return NtQueryInformationFile(handle, out ioStatus, out grantedAccess, 4, 8);
        }
    }
}
"@

Try {
    If (-not ('FileShareUtilsTest.Native' -as [type])) {
        Add-Type -TypeDefinition $NativeCode
    }
} Catch {
    Write-Host "The native helper code could not be compiled: $($_.Exception.Message)" -ForegroundColor Red
    If (-not $NoPause) { [void](Read-Host "Press Enter to close") }
    Exit 1
}

# Helper functions ===============================================================================

Function Get-ResultText([int]$Code) {
    Switch ($Code) {
        0       { 'OK' }
        5       { 'Access denied' }
        53      { 'Network path not found' }
        124     { 'Level not supported' }
        1722    { 'RPC server unavailable' }
        2310    { 'Share not found' }
        Default { (New-Object System.ComponentModel.Win32Exception -ArgumentList $Code).Message }
    }
}

Function Format-ShareType([uint32]$Type) {
    $Text = Switch ($Type -band 0xFF) {
        0       { 'Disk Drive' }
        1       { 'Print Queue' }
        2       { 'Device' }
        3       { 'IPC' }
        Default { 'Unknown' }
    }
    If ($Type -band 0x40000000) { $Text += ' Temporary' }
    If ($Type -band 0x80000000) { $Text += ' Special' }
    $Text
}

Function Format-MaxUses([uint32]$MaxUses) {
    If ($MaxUses -eq [uint32]::MaxValue) { 'unlimited' } Else { [string]$MaxUses }
}

Function Format-AccessMask([uint32]$Mask) {
    Switch ($Mask) {
        0x001F01FF { Return 'FullControl' }
        0x001301BF { Return 'Change' }
        0x001200A9 { Return 'Read' }
    }
    # Other masks: list the single file and standard rights
    Format-FlagList $Mask @(
        @(0x00000001, 'ReadData'), @(0x00000002, 'WriteData'), @(0x00000004, 'AppendData'),
        @(0x00000008, 'ReadEA'), @(0x00000010, 'WriteEA'), @(0x00000020, 'Execute'),
        @(0x00000040, 'DeleteChild'), @(0x00000080, 'ReadAttributes'), @(0x00000100, 'WriteAttributes'),
        @(0x00010000, 'Delete'), @(0x00020000, 'ReadControl'), @(0x00040000, 'WriteDAC'),
        @(0x00080000, 'WriteOwner'), @(0x00100000, 'Synchronize'))
}

Function Format-FlagList([uint32]$Value, [object[]]$Definitions) {
    $Names = ForEach ($Definition in $Definitions) {
        If ($Value -band $Definition[0]) { $Definition[1] }
    }
    If ($Names) { ($Names -join ', ') } Else { '-' }
}

# Flags of SHARE_INFO_501 / SHARE_INFO_1005
Function Format-ShareInfoFlags([uint32]$Flags) {
    $Caching = Switch ($Flags -band 0x30) {
        0x00 { 'Manual' }
        0x10 { 'Documents' }
        0x20 { 'Programs' }
        0x30 { 'None' }
    }
    $Others = Format-FlagList $Flags @(
        @(0x0800, 'ABE'), @(0x8000, 'EncryptData'), @(0x2000, 'BranchCache'),
        @(0x4000, 'ContinuouslyAvailable'), @(0x100000, 'CompressData'), @(0x1000, 'ForceLevel2Oplock'),
        @(0x0100, 'RestrictExclusiveOpens'), @(0x0200, 'ForceSharedDelete'), @(0x0400, 'AllowNamespaceCaching'),
        @(0x0001, 'DFS'), @(0x0002, 'DFSRoot'))
    '0x{0:X8} (Caching {1}; {2})' -f $Flags, $Caching, $Others
}

# ShareFlags of the SMB2 TREE_CONNECT response
Function Format-Smb2ShareFlags([uint32]$Flags) {
    $Caching = Switch ($Flags -band 0x30) {
        0x00 { 'Manual' }
        0x10 { 'Documents' }
        0x20 { 'Programs' }
        0x30 { 'None' }
    }
    $Others = Format-FlagList $Flags @(
        @(0x0800, 'ABE'), @(0x8000, 'EncryptData'), @(0x2000, 'HashV1'), @(0x4000, 'HashV2'),
        @(0x100000, 'CompressData'), @(0x1000, 'ForceLevel2Oplock'), @(0x0100, 'RestrictExclusiveOpens'),
        @(0x0200, 'ForceSharedDelete'), @(0x0400, 'AllowNamespaceCaching'), @(0x40000, 'IdentityRemoting'),
        @(0x200000, 'IsolatedTransport'), @(0x0001, 'DFS'), @(0x0002, 'DFSRoot'))
    '0x{0:X8} (Caching {1}; {2})' -f $Flags, $Caching, $Others
}

Function Format-ShareSecurity([IntPtr]$SecurityDescriptor) {
    If ($SecurityDescriptor -eq [IntPtr]::Zero) {
        Return 'no security descriptor (everyone has full access)'
    }
    $SdError = 0
    $Sddl = [FileShareUtilsTest.Native]::SdToSddl($SecurityDescriptor, [ref]$SdError)
    If (-not $Sddl) {
        Return "security descriptor could not be converted ($(Get-ResultText $SdError))"
    }
    $Script:LastSddl = $Sddl
    Format-SddlAcl $Sddl
}

# Turns the DACL of an SDDL string into "Identity: Right, ..." text
Function Format-SddlAcl([string]$Sddl) {
    $RawSd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $Sddl
    If ($null -eq $RawSd.DiscretionaryAcl) {
        Return 'NULL DACL (everyone has full access)'
    }
    $Aces = ForEach ($Ace in $RawSd.DiscretionaryAcl) {
        $Identity = $Ace.SecurityIdentifier.Value
        Try { $Identity = $Ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } Catch { }
        $Mask = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Ace.AccessMask), 0)
        $Prefix = ''
        If ($Ace.AceQualifier -eq 'AccessDenied') { $Prefix = 'Deny ' }
        '{0}{1}: {2}' -f $Prefix, $Identity, (Format-AccessMask $Mask)
    }
    If ($Aces) { ($Aces -join ', ') } Else { 'empty DACL (nobody has access)' }
}

Function Add-Result([string]$Call, [int]$Level, [int]$Code, [string]$Details) {
    $Results.Add([pscustomobject]@{
        Call    = $Call
        Level   = $Level
        Result  = (Get-ResultText $Code)
        Code    = $Code
        Details = $Details
    })
}

$GetInfoLevels = @(0, 1, 2, 501, 502, 503, 1005)
$EnumLevels    = @(0, 1, 2, 501, 502, 503)
$StructTypes   = @{
    0    = [FileShareUtilsTest.SHARE_INFO_0]
    1    = [FileShareUtilsTest.SHARE_INFO_1]
    2    = [FileShareUtilsTest.SHARE_INFO_2]
    501  = [FileShareUtilsTest.SHARE_INFO_501]
    502  = [FileShareUtilsTest.SHARE_INFO_502]
    503  = [FileShareUtilsTest.SHARE_INFO_503]
    1005 = [FileShareUtilsTest.SHARE_INFO_1005]
}

# Describes one SHARE_INFO_x structure in one line
Function Get-ShareInfoDetails([int]$Level, $Info) {
    Switch ($Level) {
        0    { "Name: $($Info.Name)" }
        1    { "Type: $(Format-ShareType $Info.Type); Description: $($Info.Remark)" }
        2    { "Path: $($Info.Path); CurrentUses: $($Info.CurrentUses); MaxUses: $(Format-MaxUses $Info.MaxUses)" }
        501  { "Type: $(Format-ShareType $Info.Type); Flags: $(Format-ShareInfoFlags $Info.Flags)" }
        502  { "Path: $($Info.Path); CurrentUses: $($Info.CurrentUses); Permissions: $(Format-ShareSecurity $Info.SecurityDescriptor)" }
        503  { "Scope: $($Info.ServerName); Path: $($Info.Path); Permissions: $(Format-ShareSecurity $Info.SecurityDescriptor)" }
        1005 { "Flags: $(Format-ShareInfoFlags $Info.Flags)" }
    }
}

$StepCount = $GetInfoLevels.Count + $EnumLevels.Count + 2
$Step = 0

# NetShareGetInfo ================================================================================

$Script:LastSddl = $null
ForEach ($Level in $GetInfoLevels) {
    $Step++
    Write-Progress -Activity $Activity -Status "NetShareGetInfo level $Level" -PercentComplete ($Step / $StepCount * 100)
    $Buffer = [IntPtr]::Zero
    Try {
        $Code = [FileShareUtilsTest.Native]::NetShareGetInfo($Server, $Share, $Level, [ref]$Buffer)
        $Details = ''
        If ($Code -eq 0) {
            $Info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Buffer, [type]$StructTypes[$Level])
            $Details = Get-ShareInfoDetails $Level $Info
        }
        Add-Result 'NetShareGetInfo' $Level $Code $Details
    } Catch {
        $ScriptErrors.Add("NetShareGetInfo level ${Level}: $($_.Exception.Message)")
    } Finally {
        If ($Buffer -ne [IntPtr]::Zero) { [void][FileShareUtilsTest.Native]::NetApiBufferFree($Buffer) }
    }
}
$GetInfoSddl = $Script:LastSddl

# NetShareEnum ===================================================================================

ForEach ($Level in $EnumLevels) {
    $Step++
    Write-Progress -Activity $Activity -Status "NetShareEnum level $Level" -PercentComplete ($Step / $StepCount * 100)
    $Buffer = [IntPtr]::Zero
    Try {
        $EntriesRead = 0
        $TotalEntries = 0
        $ResumeHandle = 0
        # -1 = MAX_PREFERRED_LENGTH, the server returns all entries at once
        $Code = [FileShareUtilsTest.Native]::NetShareEnum($Server, $Level, [ref]$Buffer, -1, [ref]$EntriesRead, [ref]$TotalEntries, [ref]$ResumeHandle)
        $Details = ''
        If ($Code -eq 0 -or $Code -eq 234) {
            $StructType = $StructTypes[$Level]
            $StructSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$StructType)
            $Entries = For ($i = 0; $i -lt $EntriesRead; $i++) {
                [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]::Add($Buffer, $i * $StructSize), [type]$StructType)
            }
            $Details = "$EntriesRead shares"
            If ($Code -eq 234) { $Details += ' (more data available, only the first part was read)' }
            If ($Level -eq 503) {
                $Scopes = @($Entries | ForEach-Object { $_.ServerName } | Sort-Object -Unique)
                $Details += "; scopes: $($Scopes -join ', ')"
            }
            $Match = $Entries | Where-Object { $_.Name -eq $Share } | Select-Object -First 1
            If ($Match -and $Level -ne 0) {
                $Details += "; $Share -> $(Get-ShareInfoDetails $Level $Match)"
            }
            $Code = 0
        }
        Add-Result 'NetShareEnum' $Level $Code $Details
    } Catch {
        $ScriptErrors.Add("NetShareEnum level ${Level}: $($_.Exception.Message)")
    } Finally {
        If ($Buffer -ne [IntPtr]::Zero) { [void][FileShareUtilsTest.Native]::NetApiBufferFree($Buffer) }
    }
}

# SMB client view of the share (FileRemoteProtocolInfo) ==========================================

$Step++
Write-Progress -Activity $Activity -Status "FileRemoteProtocolInfo on \\$Server\$Share\" -PercentComplete ($Step / $StepCount * 100)
$RootPath = "\\$Server\$Share\"
$ProtocolInfo = $null
$ProtocolError = $null
Try {
    $OpenError = 0
    # FILE_READ_ATTRIBUTES = 0x80
    $Handle = [FileShareUtilsTest.Native]::OpenDirectory($RootPath, 0x80, [ref]$OpenError)
    If ($Handle.IsInvalid) {
        $ProtocolError = "Share root could not be opened: $(Get-ResultText $OpenError)"
    } Else {
        $BufferSize = 256
        $Memory = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
        Try {
            [System.Runtime.InteropServices.Marshal]::Copy((New-Object byte[] $BufferSize), 0, $Memory, $BufferSize)
            $InfoError = [FileShareUtilsTest.Native]::QueryRemoteProtocolInfo($Handle, $Memory, $BufferSize)
            If ($InfoError -ne 0) {
                $ProtocolError = "FileRemoteProtocolInfo failed: $(Get-ResultText $InfoError)"
            } Else {
                $Bytes = New-Object byte[] $BufferSize
                [System.Runtime.InteropServices.Marshal]::Copy($Memory, $Bytes, 0, $BufferSize)
                # Offsets of FILE_REMOTE_PROTOCOL_INFO (winbase.h)
                $Version  = [BitConverter]::ToUInt16($Bytes, 0)
                $Protocol = [BitConverter]::ToUInt32($Bytes, 4)
                $Flags    = [BitConverter]::ToUInt32($Bytes, 16)
                $ProtocolInfo = [ordered]@{
                    'Structure version' = $Version
                    'Protocol'          = $(If ($Protocol -eq 0x00020000) { 'SMB (WNNC_NET_SMB)' } Else { '0x{0:X8}' -f $Protocol })
                    'Protocol version'  = '{0}.{1}, revision {2}' -f [BitConverter]::ToUInt16($Bytes, 8), [BitConverter]::ToUInt16($Bytes, 10), [BitConverter]::ToUInt16($Bytes, 12)
                    'Connection flags'  = '0x{0:X8} ({1})' -f $Flags, (Format-FlagList $Flags @(
                                              @(0x01, 'Loopback'), @(0x02, 'Offline'), @(0x04, 'PersistentHandle'),
                                              @(0x08, 'Encrypted'), @(0x10, 'Signed'), @(0x20, 'MutualAuthKerberos')))
                }
                If ($Protocol -eq 0x00020000 -and $Version -ge 2) {
                    $ServerCaps = [BitConverter]::ToUInt32($Bytes, 52)
                    $ShareCaps  = [BitConverter]::ToUInt32($Bytes, 56)
                    $ProtocolInfo['Server capabilities'] = '0x{0:X8} ({1})' -f $ServerCaps, (Format-FlagList $ServerCaps @(
                                              @(0x01, 'DFS'), @(0x02, 'Leasing'), @(0x04, 'LargeMTU'), @(0x08, 'MultiChannel'),
                                              @(0x10, 'PersistentHandles'), @(0x20, 'DirectoryLeasing'), @(0x40, 'Encryption'),
                                              @(0x80, 'Notifications')))
                    $ProtocolInfo['Share capabilities'] = '0x{0:X8} ({1})' -f $ShareCaps, (Format-FlagList $ShareCaps @(
                                              @(0x08, 'DFS'), @(0x10, 'ContinuousAvailability'), @(0x20, 'ScaleOut'),
                                              @(0x40, 'Cluster'), @(0x80, 'Asymmetric'), @(0x100, 'RedirectToOwner')))
                    $ProtocolInfo['Share flags'] = Format-Smb2ShareFlags ([BitConverter]::ToUInt32($Bytes, 60))
                }
                If ($Protocol -eq 0x00020000 -and $Version -ge 4) {
                    $ShareType = $Bytes[64]
                    $ProtocolInfo['Share type'] = Switch ($ShareType) { 1 { 'Disk' } 2 { 'Pipe' } 3 { 'Print' } 0 { '0 (not reported)' } Default { [string]$ShareType } }
                }
            }
        } Finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Memory)
        }
        $Handle.Dispose()
    }
} Catch {
    $ScriptErrors.Add("FileRemoteProtocolInfo: $($_.Exception.Message)")
}

# Account and dialect as seen by the SMB client (Get-SmbConnection needs an elevated session)
$Connection = $null
$SmbError = $null
Try {
    $Connection = Get-SmbConnection -ServerName $Server -ErrorAction SilentlyContinue -ErrorVariable SmbError |
        Where-Object { $_.ShareName -eq $Share } | Select-Object -First 1
} Catch {
    $SmbError = $_
}

# Experimental: access granted to an open with MAXIMUM_ALLOWED ===================================

$Step++
Write-Progress -Activity $Activity -Status "Open \\$Server\$Share\ with MAXIMUM_ALLOWED" -PercentComplete ($Step / $StepCount * 100)
$GrantedText = $null
Try {
    $OpenError = 0
    # MAXIMUM_ALLOWED = 0x02000000
    $Handle = [FileShareUtilsTest.Native]::OpenDirectory($RootPath, 0x02000000, [ref]$OpenError)
    If ($Handle.IsInvalid) {
        $GrantedText = "Share root could not be opened: $(Get-ResultText $OpenError)"
    } Else {
        $Granted = [uint32]0
        $Status = [FileShareUtilsTest.Native]::QueryGrantedAccess($Handle, [ref]$Granted)
        If ($Status -eq 0) {
            $GrantedText = '0x{0:X8} ({1})' -f $Granted, (Format-AccessMask $Granted)
        } Else {
            $GrantedText = "Query failed: $(Get-ResultText ([FileShareUtilsTest.Native]::RtlNtStatusToDosError($Status)))"
        }
        $Handle.Dispose()
    }
} Catch {
    $ScriptErrors.Add("MAXIMUM_ALLOWED test: $($_.Exception.Message)")
}

Write-Progress -Activity $Activity -Completed

# Output =========================================================================================

Write-Host ''
Write-Host "Share information test for \\$Server\$Share" -ForegroundColor Cyan
$LocalAccount = 'unknown'
Try { $LocalAccount = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } Catch { }
Write-Host "Local account : $LocalAccount"
If ($Connection) {
    Write-Host ("SMB session   : user {0}, credential {1}, dialect {2}, signed {3}, encrypted {4}" -f `
        $Connection.UserName, $Connection.Credential, $Connection.Dialect, $Connection.Signed, $Connection.Encrypted)
} ElseIf ($SmbError) {
    Write-Host "SMB session   : not available, Get-SmbConnection: $(@($SmbError)[0].Exception.Message) (needs an elevated session)"
} Else {
    Write-Host 'SMB session   : not available (Get-SmbConnection gave no result for this share)'
}

Write-Host ''
Write-Host 'Information levels (the server decides with the account of the network logon):' -ForegroundColor Cyan
$Results | Format-Table Call, Level, Result, Details -Wrap -AutoSize | Out-Host

If ($GetInfoSddl) {
    Write-Host "Share permissions as SDDL : $GetInfoSddl"
    Write-Host ''
}

Write-Host 'SMB client view of the share (FileRemoteProtocolInfo, works without admin rights):' -ForegroundColor Cyan
If ($ProtocolInfo) {
    [pscustomobject]$ProtocolInfo | Format-List | Out-Host
} Else {
    Write-Host "  $ProtocolError"
    Write-Host ''
}

Write-Host 'Experimental: access granted on the share root with MAXIMUM_ALLOWED' -ForegroundColor Cyan
Write-Host "  $GrantedText"
Write-Host '  Combines share and NTFS permissions of the root folder. Unverified whether the SMB client'
Write-Host '  reports the real value from the server - compare with the permissions you know.'
Write-Host ''

# Summary
Function Test-Readable([int[]]$Levels) {
    $Hit = $Results | Where-Object { $_.Call -eq 'NetShareGetInfo' -and $Levels -contains $_.Level -and $_.Code -eq 0 }
    If ($Hit) { 'yes' } Else { 'no' }
}
Write-Host 'Summary for this account' -ForegroundColor Cyan
Write-Host "  Flags (ABE, caching, encryption) : $(Test-Readable @(501, 1005))   (levels 501, 1005)"
Write-Host "  Path and connection count        : $(Test-Readable @(2, 502, 503))   (levels 2, 502, 503)"
Write-Host "  Share permissions                : $(Test-Readable @(502, 503))   (levels 502, 503)"
If ((Test-Readable @(502)) -eq 'no') {
    Write-Host ''
    Write-Host '  Windows servers return path and permissions only to Administrators and Server Operators' -ForegroundColor Yellow
    Write-Host '  (older versions also Print Operators and Power Users). On Windows Server 2022 and later,' -ForegroundColor Yellow
    Write-Host '  membership in "Access Control Assistance Operators" (S-1-5-32-579) on the server should' -ForegroundColor Yellow
    Write-Host '  be enough. Start a new logon after changing the group membership.' -ForegroundColor Yellow
}
Write-Host ''

If ($OutFile) {
    Try { Stop-Transcript | Out-Null } Catch { }
}

If ($ScriptErrors.Count -eq 0) {
    Write-Host 'Test finished without script errors.' -ForegroundColor Green
} Else {
    Write-Host "Test finished with $($ScriptErrors.Count) script error(s):" -ForegroundColor Red
    ForEach ($ScriptError in $ScriptErrors) { Write-Host "  $ScriptError" -ForegroundColor Red }
}

If (-not $NoPause) {
    [void](Read-Host 'Press Enter to close')
}
