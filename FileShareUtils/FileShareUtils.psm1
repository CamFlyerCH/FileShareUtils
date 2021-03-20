# PowerShell Module FileShareUtils from Jean-Marc Ulrich
# https://github.com/CamFlyerCH/FileShareUtils
#
# Large parts of the used code where posted by
# Micky Balladelli micky@balladelli.com on https://balladelli.com/category/smb/
# Alexander in his Kazun PowerShell blog https://kazunposh.wordpress.com/
# Jordan Borean https://gist.github.com/jborean93/f60da33b08f8e1d5e0ef545b0a4698a0

# Code to access the netapi32, kernel32 and advapi32 functions
Add-Type -TypeDefinition @" 
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Security.AccessControl;

public class Netapi
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_0
    {
		[MarshalAs(UnmanagedType.LPWStr)] public String Name;
    }

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		public uint Type;
		[MarshalAs(UnmanagedType.LPWStr)] public string Remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_2
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		public uint Type;
		[MarshalAs(UnmanagedType.LPWStr)] public string Remark;
		public uint Permissions;
		public uint MaxUses;
		public uint CurrentUses;
		[MarshalAs(UnmanagedType.LPWStr)] public string Path;
		[MarshalAs(UnmanagedType.LPWStr)] public string Password;
   }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_502
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		public uint Type;
		[MarshalAs(UnmanagedType.LPWStr)] public string Remark;
		public int Permissions;
		public int MaxUses;
		public int CurrentUses;
		[MarshalAs(UnmanagedType.LPWStr)] public string Path;
		[MarshalAs(UnmanagedType.LPWStr)] public string Password;
		public int Reserved;
		public IntPtr SecurityDescriptor;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_503
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		public uint Type;
		[MarshalAs(UnmanagedType.LPWStr)] public string Remark;
		public uint Permissions;
		public uint MaxUses;
		public uint CurrentUses;
		[MarshalAs(UnmanagedType.LPWStr)] public string Path;
		[MarshalAs(UnmanagedType.LPWStr)] public string Password;
		[MarshalAs(UnmanagedType.LPWStr)] public string ServerName;
		public uint Reserved;
		public IntPtr SecurityDescriptor;
    }

	[DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
    public static extern uint NetShareEnum(
		[In,MarshalAs(UnmanagedType.LPWStr)] string server,
		int level,
		out IntPtr bufptr,
		int prefmaxlen,
		ref Int32 entriesread,
		ref Int32 totalentries,
		ref Int32 resume_handle);

	[DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
    public static extern int NetApiBufferFree(IntPtr buffer);

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STAT_SERVER_0
    {
	  public uint Start;
	  public uint FOpens;
	  public uint DevOpens;
	  public uint JobsQueued;
	  public uint SOpens;
	  public uint STimedOut;
	  public uint SerrorOut;
	  public uint PWerrors;
	  public uint PermErrors;
	  public uint SysRrrors;
	  public uint bytesSent_low;
	  public uint bytesSent_high;
	  public uint bytesRcvd_low;
	  public uint BytesRcvd_high;
	  public uint AvResponse;
	  public uint ReqNufNeed;
	  public uint BigBufNeed;
    }

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STAT_WORKSTATION_0
    {
	  public long StatisticsStartTime;
	  public long BytesReceived;
	  public long SmbsReceived;
	  public long PagingReadBytesRequested;
	  public long NonPagingReadBytesRequested;
	  public long CacheReadBytesRequested;
	  public long NetworkReadBytesRequested;
	  public long BytesTransmitted;
	  public long SmbsTransmitted;
	  public long PagingWriteBytesRequested;
	  public long NonPagingWriteBytesRequested;
	  public long CacheWriteBytesRequested;
	  public long NetworkWriteBytesRequested;
	  public uint InitiallyFailedOperations;
	  public uint FailedCompletionOperations;
	  public uint ReadOperations;
	  public uint RandomReadOperations;
	  public uint ReadSmbs;
	  public uint LargeReadSmbs;
	  public uint SmallReadSmbs;
	  public uint WriteOperations;
	  public uint RandomWriteOperations;
	  public uint WriteSmbs;
	  public uint LargeWriteSmbs;
	  public uint SmallWriteSmbs;
	  public uint RawReadsDenied;
	  public uint RawWritesDenied;
	  public uint NetworkErrors;
	  public uint Sessions;
	  public uint FailedSessions;
	  public uint Reconnects;
	  public uint CoreConnects;
	  public uint Lanman20Connects;
	  public uint Lanman21Connects;
	  public uint LanmanNtConnects;
	  public uint ServerDisconnects;
	  public uint HungSessions;
	  public uint UseCount;
	  public uint FailedUseCount;
	  public uint CurrentCommands;
    }

	[DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
    public static extern uint NetStatisticsGet(
		[In,MarshalAs(UnmanagedType.LPWStr)] string server,
		[In,MarshalAs(UnmanagedType.LPWStr)] string service,
		int level,
		int options,
		out IntPtr bufptr);

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SESSION_INFO_0
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
    }

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SESSION_INFO_1
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		[MarshalAs(UnmanagedType.LPWStr)] public string Username;
		public uint NumOpens;
		public uint Time;
		public uint IdleTime;
		public uint UserFlags;
    }

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SESSION_INFO_2
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		[MarshalAs(UnmanagedType.LPWStr)] public string Username;
		public uint NumOpens;
		public uint Time;
		public uint IdleTime;
		public uint UserFlags;
		[MarshalAs(UnmanagedType.LPWStr)] public string ConnectionType;
    }

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SESSION_INFO_10
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		[MarshalAs(UnmanagedType.LPWStr)] public string Username;
		public uint Time;
		public uint IdleTime;
    }

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SESSION_INFO_502
    {
		[MarshalAs(UnmanagedType.LPWStr)] public string Name;
		[MarshalAs(UnmanagedType.LPWStr)] public string Username;
		public uint NumOpens;
		public uint Time;
		public uint IdleTime;
		public uint UserFlags;
		[MarshalAs(UnmanagedType.LPWStr)] public string ConnectionType;
		[MarshalAs(UnmanagedType.LPWStr)] public string Transport;
    }

	[DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
    public static extern uint NetSessionEnum(
		[In,MarshalAs(UnmanagedType.LPWStr)] string server,
		int client,
		int user,
		int level,
		out IntPtr bufptr,
		int prefmaxlen,
		ref Int32 entriesread,
		ref Int32 totalentries,
		ref Int32 resume_handle);

    [DllImport("Netapi32.dll", SetLastError=true)]
    public static extern int NetSessionDel(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
        [MarshalAs(UnmanagedType.LPWStr)] string username);

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FILE_INFO_2
    {
		public uint FileID;
    }
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FILE_INFO_3
    {
		public uint FileID;
		public uint Permissions;
		public uint NumLocks;
		[MarshalAs(UnmanagedType.LPWStr)] public string Path;
		[MarshalAs(UnmanagedType.LPWStr)] public string User;
    }

	[DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]
    public static extern uint NetFileEnum(
		[In,MarshalAs(UnmanagedType.LPWStr)] string server,
		[In,MarshalAs(UnmanagedType.LPWStr)] string path,
		int user,
		int level,
		out IntPtr bufptr,
		int prefmaxlen,
		ref Int32 entriesread,
		ref Int32 totalentries,
		ref Int32 resume_handle);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public extern static int NetFileClose(string servername, uint fileid);

	[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
	public static extern bool GetSecurityDescriptorDacl(
		IntPtr pSecurityDescriptor,
		[MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent,
		ref IntPtr pDacl,
		[MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted
	);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern bool GetAclInformation(
		IntPtr pAcl,
		ref ACL_SIZE_INFORMATION pAclInformation,
		uint nAclInformationLength,
		ACL_INFORMATION_CLASS dwAclInformationClass
	);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetAce(
		IntPtr aclPtr,
		int aceIndex,
		out IntPtr acePtr
	);

	[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetLengthSid(
        IntPtr pSID
    );

	[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertSidToStringSid(
        [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
        out IntPtr ptrSid
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsValidSecurityDescriptor(
		IntPtr pSecurityDescriptor
	);

	[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
	public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
		IntPtr pSecurityDescriptor,
		int SDRevision,
        int SecurityInfo,
		out IntPtr StringSDL,
        out int StringLength
	);

	[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
	public static extern int ConvertStringSecurityDescriptorToSecurityDescriptor(
		IntPtr StringSDL,
		int SDRevision,
		out IntPtr pSecurityDescriptor,
        out int pSecurityDescriptorSize
	);


	[StructLayout(LayoutKind.Sequential)]
	public struct ACL_SIZE_INFORMATION
	{
		public uint AceCount;
		public uint AclBytesInUse;
		public uint AclBytesFree;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct ACE_HEADER
	{
		public byte AceType;
		public byte AceFlags;
		public short AceSize;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct ACCESS_ALLOWED_ACE
	{
		public ACE_HEADER Header;
		public int Mask;
		public int SidStart;
	}

	public enum ACL_INFORMATION_CLASS
	{
		AclRevisionInformation = 1,
		AclSizeInformation
	}

    public enum CacheType : uint
    {
        Manual    = 0x00,
        Documents = 0x10,
        Programs  = 0x20,
        None      = 0x30,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1005
    {
        public uint shi1005_flags;
    }

    public const int FLAGS_ACCESS_BASED_DIRECTORY_ENUM = 0x0800;

    public enum Share_Type : uint
    {
        STYPE_DISKTREE  = 0x00000000,   // Disk Drive
        STYPE_PRINTQ    = 0x00000001,   // Print Queue
        STYPE_DEVICE    = 0x00000002,   // Communications Device
        STYPE_IPC       = 0x00000003,   // InterProcess Communications
        STYPE_SPECIAL   = 0x80000000,   // Special share types (C$, ADMIN$, IPC$, etc)
        STYPE_TEMPORARY = 0x40000000    // Temporary share
    }

    public enum LogicalShareRights : uint
    {
        FullControl      = 0x001f01ff,
        Read             = 0x001200a9,
        Change           = 0x001301bf
    }

    [DllImport("Netapi32.dll", SetLastError=true)]
    public static extern int NetShareGetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string netName,
        Int32 level,
        out IntPtr bufPtr );

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareSetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string netName,
        Int32 level,
        IntPtr buf,
        IntPtr parm_err );

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareAdd(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        Int32 level,
        IntPtr buf,
        IntPtr parm_err );

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceEx(string lpDirectoryName,
	    out ulong lpFreeBytesAvailable,
	    out ulong lpTotalNumberOfBytes,
	    out ulong lpTotalNumberOfFreeBytes);

    [DllImport("Netapi32.dll", SetLastError=true)]
    public static extern int NetShareDel(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string netName,
        Int32 reserved);

}

namespace Win32
{
    public class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public UInt32 Status;
            public UInt32 Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NT_Trans_Data
        {
            public UInt32 NumberOfSnapShots;
            public UInt32 NumberOfSnapShotsReturned;
            public UInt32 SnapShotArraySize;
            // Omit SnapShotMultiSZ because we manually get that string based on the struct results
        }
    }

    public class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            FileSystemRights dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern UInt32 NtFsControlFile(
            SafeFileHandle hDevice,
            IntPtr Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            ref NativeHelpers.IO_STATUS_BLOCK IoStatusBlock,
            UInt32 FsControlCode,
            IntPtr InputBuffer,
            UInt32 InputBufferLength,
            IntPtr OutputBuffer,
            UInt32 OutputBufferLength);

        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlNtStatusToDosError(
            UInt32 Status);
    }
}

"@

# Helper - Functions ===========================================================================

Function Get-LastWin32ExceptionMessage {
    <#
        .SYNOPSIS
            Converts a Win32 Status Code to a more descriptive error message.

        .PARAMETER ErrorCode
            The Win32 Error Code to convert

        .NOTES
            Name: Get-LastWin32ExceptionMessage
            Author: Jordan Borean (@jborean93) <jborean93@gmail.com>

        .EXAMPLE
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Get-LastWin32Exception -ErrorCode $LastError
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $ErrorCode
    )

    $Exp = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $ErrorCode
    $ExpMsg = "{0} (Win32 ErrorCode {1} - 0x{1:X8})" -f $Exp.Message, $ErrorCode
    return $ExpMsg
}

Function Get-DNSGet-DNSReverseLookup{
    Param(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$IP
    )
    Process {
        IF($IP.Contains(".")){
            Trap{$IP;continue}
            [System.Net.Dns]::GetHostEntry($IP).HostName
        } Else {
            $IP
        }
    }
}

Function Convert-ShareACLToText($ShareACL,$SortACL){
    #Seperators in the String
    $InACLseperator = ","
    $InACEseperator = "|"
    $ShareACLText = ""

    $ShareACLArray = $ShareACL.Access

    If($ShareACLArray.Count -ne 0){
        If($SortACL){
            $ShareACLArray = $ShareACLArray | Sort-Object -Property @{Expression="AccessControlType";Descending=$true}, @{Expression="IdentityReference";Descending=$false}
        }

        # Build string
        ForEach($ShareACE in $ShareACLArray){
            $AccessRight = $ShareACE.FileSystemRights
            If($AccessRight -eq "ReadAndExecute, Synchronize") {$AccessRight = "Read"}
            If($AccessRight -eq "Modify, Synchronize") {$AccessRight = "Change"}
            If($ShareACE.AccessControlType -ne "Allow") {$AccessRight = "Deny-" + $AccessRight}

            $ShareACLText += ($ShareACE.IdentityReference.Value + $InACEseperator + $AccessRight + $InACLseperator)
        }

        # Cut last seperator
        $Return = ($ShareACLText.SubString(0,$ShareACLText.Length - 1))
    } Else {$Return = ""}
    $Return
}

Function Convert-ACLTextToShareACL($UnsortedACLText){
    #Seperators in the String
    $InACLseperator = ","
    $InACEseperator = "|"
    $NewACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity

    $ACETexts = $UnsortedACLText -split $InACLseperator

    ForEach($ACEText in $ACETexts){
        If($ACEText){
            $OutputIdentityReference = $ACEText.substring(0,$ACEText.indexof($InACEseperator))
            $OutputFileSystemRights = $ACEText.substring($ACEText.indexof($InACEseperator)+$InACEseperator.length,$ACEText.length-($ACEText.indexof($InACEseperator)+$InACEseperator.length))

            If($OutputFileSystemRights.substring(0,4) -eq "Deny"){
                $OutputFileSystemRights = "FullControl"
                $OutputAccessControlType = "Deny"
            } Else {
                $OutputAccessControlType = "Allow"
            }

            If($OutputFileSystemRights -eq "Read") {$OutputFileSystemRights = "ReadAndExecute, Synchronize"}
            If($OutputFileSystemRights -eq "Change") {$OutputFileSystemRights = "Modify, Synchronize"}

            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($OutputIdentityReference, $OutputFileSystemRights, "None", "None", $OutputAccessControlType)
            Try{
                $NewACLObject.AddAccessRule($rule)
            } Catch {
                $ErrorMessage = $error[0].ToString()
                Throw ("Error for Identity $OutputIdentityReference : " + $ErrorMessage)
            }
        }
    }
    $NewACLObject
}

Function Convert-SDtoSDDL($ptr2SD,$SECURITY_INFORMATION){
    #OWNER_SECURITY_INFORMATION	1	der Eigentümer wird konvertiert
    #GROUP_SECURITY_INFORMATION	2	die primäre Gruppe wird konvertiert
    #DACL_SECURITY_INFORMATION	4	die DACL Zugriffskontrollliste wird konvertiert
    #SACL_SECURITY_INFORMATION	8	die System Zugriffskontrollliste wird konvertiert
    #LABEL_SECURITY_INFORMATION	16	die Mandantory Zugriffskontrolleinträge werden konvertiert
    #$SECURITY_INFORMATION = 4
    $SDDL_REVISION_1 = 1

	$return = [Netapi]::IsValidSecurityDescriptor($ptr2SD)

    $sddlptr = [IntPtr]::Zero
    $sddllength = [IntPtr]::Zero
	$return = [Netapi]::ConvertSecurityDescriptorToStringSecurityDescriptor($ptr2SD,$SDDL_REVISION_1,$SECURITY_INFORMATION,[ref]$sddlptr,[ref]$sddllength)
    If($return -ne $True){
        Throw ("Error during ConvertSecurityDescriptorToStringSecurityDescriptor: " + (Get-LastWin32ExceptionMessage $return))
    }
    $sddl = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($sddlptr)
    $sddl
}

Function Convert-SDDLToACL {
    <#
        .Synopsis
            Convert SDDL String to ACL Object
        .DESCRIPTION
            Converts one or more SDDL Strings to a standard powershell format.
        .EXAMPLE
            Convert-SDDLToACL -SDDLString (get-acl .\path).sddl
        .EXAMPLE
            Convert-SDDLToACL -SDDLString “O:S-1-5-21-1559760989-2529464504-629046386-3226G:DUD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-1557760989-2587764504-629046386-1166)”
        .NOTES
            Robert Amartinesei
            https://poshscripter.wordpress.com/2017/04/27/sddl-conversion-with-powershell/
    #>
    [Cmdletbinding()]
    param (
        #One or more strings of SDDL syntax.
        [string[]]$SDDLString
    )
    foreach ($SDDL in $SDDLString) {
        $ACLObject = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
        $ACLObject.SetSecurityDescriptorSddlForm($SDDL)
        $ACLObject
    }
}

Function Invoke-EnumerateSnapshots {
    <#
        .SYNOPSIS
            Invokes NtFsControlFile with the handle and buffer size specified.

        .DESCRIPTION
            This cmdlet is defined to invoke NtFsControlFile with the
            FSCTL_SRV_ENUMERATE_SNAPSHOTS control code.

        .PARAMETER Handle
            A SafeFileHandle of the opened UNC path. This should be retrieved with
            CreateFileW.

        .PARAMETER BufferSize
            The buffer size to initialise the output buffer. This should be a minimum
            of ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][Win32.NativeHelpers+NT_Trans_Data]) + 4).
            See Examples on how to invoke this

        .PARAMETER ScriptBlock
            The script block to invoke after the raw output buffer is converted to the
            NT_Trans_Data structure.

        .NOTES
            Name: Invoke-EnumerateSnapshots
            Author: Jordan Borean (@jborean93) <jborean93@gmail.com>
            OUTPUT : Array of strings with the full snapshot paths

        .EXAMPLE
            $BufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][Win32.NativeHelpers+NT_Trans_Data]) + 4)
            Invoke-EnumerateSnapshots -Handle $Handle -BufferSize $BufferSize -ScriptBlock {
                $TransactionData = $args[1]

                if ($TransactionData.NumberOfSnapShots -gt 0) {
                    $NewBufferSize = $BufferSize + $TransactionData.SnapShotArraySize

                    Invoke-EnumerateSnapshots -Handle $Handle -BufferSize $NewBufferSize -ScriptBlock {
                        $OutBuffer = $args[0]
                        $TransactionData = $args[1]

                        $SnapshotPtr = [System.IntPtr]::Add($OutBuffer, $TransDataSize)
                        $SnapshotString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($SnapshotPtr,
                            $TransactionData.SnapShotArraySize / 2)

                        $SnapshotString.Split([char[]]@("`0"), [System.StringSplitOptions]::RemoveEmptyEntries)
                    }
                }
            }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]
        $Handle,

        [Parameter(Mandatory = $true)]
        [System.Int32]
        $BufferSize,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock
    )

    # Allocate new memory based on the buffer size
    $OutBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
    try {
        $IOBlock = New-Object -TypeName Win32.NativeHelpers+IO_STATUS_BLOCK

        # Call NtFsControlFile with the handle and FSCTL_SRV_ENUMERATE_SNAPSHOTS code
        $Result = [Win32.NativeMethods]::NtFsControlFile($Handle, [System.IntPtr]::Zero, [System.IntPtr]::Zero,
            [System.IntPtr]::Zero, [Ref]$IOBlock, 0x00144064, [System.IntPtr]::Zero, 0, $OutBuffer, $BufferSize)

        if ($Result -ne 0) {
            # If the result was not 0 we need to convert the NTSTATUS code to a Win32 code
            $Win32Error = [Win32.NativeMethods]::RtlNtStatusToDosError($Result)
            $Msg = Get-LastWin32ExceptionMessage -ErrorCode $Win32Error
            Write-Error -Message "NtFsControlFile failed - $Msg"
            return
        }

        # Convert the OutBuffer pointer to a NT_Trans_Data structure
        $TransactionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            $OutBuffer,
            [Type][Win32.NativeHelpers+NT_Trans_Data]
        )

        # Invoke out script block that parses the data and outputs whatever it needs. We pass in both the
        # OutBuffer and TransactionData as arguments
        &$ScriptBlock $OutBuffer $TransactionData
    } finally {
        # Make sure we free the unmanaged memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($OutBuffer)
    }
}



# Module - Functions =============================================================================



Function Get-NetShares{
    <#
        .SYNOPSIS
            Retrieves a list of all network shares from a local or remote computer

        .DESCRIPTION
            Retrieves basic parameters of all shares from a local or remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Level
            NetShareEnum info level. Defaults 502, but you can use 1 for listing shares without admin rights

        .NOTES
            Name: Get-NetShares
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 10.05.2018
                1.1 //Changed to support servers with more than ~250 shares
                1.2 //Added level parameter to list shares without admin rights

        .EXAMPLE
            Get-NetShares -Server 'srv1234'

            Description
            -----------
            Gets the information of all shares of a remote server
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=1,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet(502,1)]
        [Int]$Level = 502
    )
    Begin {
        # We want to query the 502 datas
	    $buffer = 0
	    $entries = 0
	    $total = 0
	    $handle = 0
        $Shares = @()
        If($Level -eq 1){
            $struct = New-Object Netapi+SHARE_INFO_1
        } else {
            $struct = New-Object Netapi+SHARE_INFO_502
        }
        $ReadFinished = $False

        While($ReadFinished -eq $False){
            $return = [Netapi]::NetShareEnum($Server, $level,[ref]$buffer,-1,[ref]$entries, [ref]$total,[ref]$handle)

            If($return -ne 0 -and $return -ne 234){
               Throw ("Error during NetShareEnum: " + (Get-LastWin32ExceptionMessage $return))
            }

            If($entries -eq $total -and $return -eq 0){$ReadFinished = $True}

		    $offset = $buffer.ToInt64()
		    $increment = [System.Runtime.Interopservices.Marshal]::SizeOf([System.Type]$struct.GetType())

		    For ($i = 0; $i -lt $entries; $i++)
		    {
                # Define output object
	            $Share = New-Object -TypeName PSObject
                $ptr = New-Object system.Intptr -ArgumentList $offset

                $str502 = [system.runtime.interopservices.marshal]::PtrToStructure($ptr, [System.Type]$struct.GetType())
			    $offset = $ptr.ToInt64()
	            $offset += $increment

                # Get the easy data
                $Share | Add-Member Server $Server
                $Share | Add-Member Name $str502.Name
                $Share | Add-Member Path $str502.Path
                $Share | Add-Member Description $str502.Remark
                $Share | Add-Member CurrentUses $str502.CurrentUses

                # Get the type
                If (($str502.Type -band 0x00000001) -ne 0 -and ($str502.Type -band 0x00000002) -ne 0){
                    $Type = "IPC"
                } Else {
                    If ($str502.Type -band 0x00000001){
                        $Type = "Print Queue"
                    } Else {
                        If ($str502.Type -band 0x00000002){
                            $Type = "Device"
                        } Else {
                            $Type = "Disk Drive"
                        }
                    }
                }
                If (($str502.Type -band 0x40000000) -ne 0){
                    $Type = $Type + " Temporary"
                }
                If (($str502.Type -band 0x80000000) -ne 0){
                    $Type = $Type + " Special"
                }
                $Share | Add-Member Type $Type

                $Shares += $Share
            }
        }

        $Shares | Sort-Object Path,Name

        # Cleanup memory
        [Netapi]::NetApiBufferFree($buffer) | Out-Null
    }
}


Function Get-NetShare{
    <#
        .SYNOPSIS
            Retrieves specified network share information from a local or remote computer

        .DESCRIPTION
            Retrieves all parameters and permissions form one defined network share
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Name
            Name of the share

        .PARAMETER Server
            Computername on the network, local if left blank

        .NOTES
            Name: Get-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 10.05.2018

        .EXAMPLE
            Get-NetShare -Name 'TestShare' -Server 'srv1234'

            Description
            -----------
            Gets the information of the share named "TestShare" of a remote server
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Name,

        [Parameter(Position=1,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower()
    )
    Begin {
        # We want to query the 502 data first
        $bufptr = [IntPtr]::Zero
        $struct = New-Object Netapi+SHARE_INFO_502
        $return = [Netapi]::NetShareGetInfo($Server,$Name,502,[ref]$bufptr)

        If($return -eq 0){
            $str502 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr,[System.Type]$struct.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo for $Name : " + (Get-LastWin32ExceptionMessage $return))
        }

        # Now read the flags
        $bufptr = [IntPtr]::Zero
        $struct = New-Object Netapi+SHARE_INFO_1005
        $return = [Netapi]::NetShareGetInfo($Server,$Name,1005,[ref]$bufptr)

        If($return -eq 0){
            $str1005 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr,[System.Type]$struct.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo 1005: " + (Get-LastWin32ExceptionMessage $return))
        }

        # Define output object
        $Share = New-Object -TypeName PSObject

        # Get the easy data
        $Share | Add-Member Server $Server
        $Share | Add-Member Name $str502.Name
        $Share | Add-Member Path $str502.Path
        $Share | Add-Member Description $str502.Remark

        # Get infos contained in the flags
        $ShareFlags = $str1005.shi1005_flags

        If ($ShareFlags -band 0x0800){
            $Share | Add-Member ABE "Enabled"
        } Else {
            $Share | Add-Member ABE "Disabled"
        }

        # Offline (client side caching) configuration
        $Share | Add-Member CachingMode ([enum]::GetValues([Netapi+CacheType]) | Where-Object {$_.value__ -eq ($ShareFlags -band 0x0030)})

        # Prepare to read ACL
	    If ($str502.SecurityDescriptor -ne 0){

            #$ShareACL = SDtoACL $str502.SecurityDescriptor
            #$ShareACLText = ACLArrayToACLText $ShareACL $True
            $ShareACLSSDL = Convert-SDtoSDDL $str502.SecurityDescriptor 4 # 15 or 4
            $ShareACL = Convert-SDDLToACL -SDDLString $ShareACLSSDL
            #$ShareACLText = $ShareACL.AccessToString
            $ShareACLText = Convert-ShareACLToText $ShareACL $True

	    } # EndIf SD present


        $Share | Add-Member ShareACLText $ShareACLText

        $Share | Add-Member CurrentUses $str502.CurrentUses
        $Share | Add-Member ConcurrentUserLimit $str502.MaxUses

        If ($ShareFlags -band 0x2000){
            $Share | Add-Member BranchCache "Enabled"
        } Else {
            $Share | Add-Member BranchCache "Disabled"
        }

        $Share | Add-Member Flags $ShareFlags

        # Get the type
        Switch ($str502.Type){
            0x00000000    {$Share | Add-Member Type "Disk Drive"}
            0x00000001    {$Share | Add-Member Type "Print Queue"}
            0x00000002    {$Share | Add-Member Type "Device"}
            0x00000003    {$Share | Add-Member Type "IPC"}
            0x80000000    {$Share | Add-Member Type "Special"}
            0x40000000    {$Share | Add-Member Type "Temporary"}
        }

        $Share | Add-Member ShareSDDL $ShareACLSSDL

        $Share | Add-Member ShareACL $ShareACL

        # Cleanup memory
        [Netapi]::NetApiBufferFree($bufptr) | Out-Null

        $Share

    }
}

Function Get-NetFileShares{
    <#
        .SYNOPSIS
            Retrieves a list of all file shares from a local or remote computer with permissions and flags

        .DESCRIPTION
            Retrieves basic parameters of all shares from a local or remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .NOTES
            Name: Get-NetFileShares
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 10.05.2018

        .EXAMPLE
            Get-NetFileShares -Server 'srv1234'

            Description
            -----------
            Gets the information of all shares of a remote server
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower()
    )
    Begin {
        $FileShareList = Get-NetShares -Server $Server | Sort-Object Server,Path,Name

        ForEach ($FileShare in $FileShareList){
            IF ($FileShare.Type -eq "Disk Drive"){
                Get-NetShare -Name $FileShare.Name -Server $FileShare.Server | Select-Object -Property Server,Name,Path,Description,ABE,CachingMode,ShareACLText,CurrentUses
            }
        }
    }
}


Function New-NetShare{
    <#
        .SYNOPSIS
            Creates a network file share local or on a remote computer

        .DESCRIPTION
            Creates a network share
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Name
            Name of the share

        .PARAMETER Path
            Local disk path to share

        .PARAMETER Description
            The description/remark of the share

        .PARAMETER Permissions
            Permissions on the share itself. Special format: Every permission is seperated by a comma and the identity and the access right are seperated by a |
            Default: Everyone|FullControl
            Possible Permissions: Read, Change, FullControl, Deny-FullControl
            Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, <NETBIOSDOMAINNAME>\<sAMAccountName> (domain objects)

        .PARAMETER ABE
            Access based enumaration, can be Enabled or Disabled (default)

        .PARAMETER CachingMode
            Offline Folder configuration, can be Manual (default), "None", "Documents" (all documents are automaticaly offline available), "Programs" ("Performance option", all files are automaticaly offline available)

        .PARAMETER MaxUses
            Allowed connections to the share. Default is -1 that equals maximum


        .NOTES
            Name: New-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 17.05.2018

        .EXAMPLE
            New-NetShare -Server 'srv1234' -Name 'TestShare' -Path 'D:\Data'

            Description
            -----------
            Shares the path D:\Data on the server named srv1234 as TestShare
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Name,

        [Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path,

        [Parameter(Position=3,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Description,

        [Parameter(Position=4,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Permissions,  # = "Everyone|FullControl"

        [Parameter(Position=5,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Disabled", "Enabled", IgnoreCase = $true)]  # FolderEnumerationMode AccessBased, Unrestricted
        [string]$ABE = "Disabled",

        [Parameter(Position=6,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Manual", "None", "Documents", "Programs", IgnoreCase = $true)]
        [string]$CachingMode = "Manual",

        [Parameter(Position=7,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Int]$MaxUses = -1

    )
    Begin {
        $struct = New-Object Netapi+SHARE_INFO_502
        $struct.Name = $Name
        $struct.Type = 0                 # 0 -> STYPE_DISKTREE
        $struct.Path = $Path
        $struct.Remark = $Description
        $struct.Permissions = 0
        $struct.MaxUses = $MaxUses
        $paramerror = 0

        $structsize = [System.Runtime.InteropServices.Marshal]::SizeOf($struct)
        [IntPtr]$bufptr = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($structsize)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($struct,$bufptr,$false)

        $return = [Netapi]::NetShareAdd($Server,502,$bufptr,$paramerror)

        [Netapi]::NetApiBufferFree($bufptr) | Out-Null

        If($return -ne 0){
            Throw ("Error during NetShareAdd: " + (Get-LastWin32ExceptionMessage $return))
        }

        $return = Set-NetShare -Server $Server -Name $Name -Description $Description -Permissions $Permissions -ABE $ABE -CachingMode $CachingMode -MaxUses $MaxUses

    }
}

Function Set-NetShare{
    <#
        .SYNOPSIS
            Changes options on a network file share local or on a remote computer

        .DESCRIPTION
            Can modify all changeable options of a file share local or on a remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Name
            Name of the share

        .PARAMETER Description
            The description/remark of the share

        .PARAMETER Permissions
            Permissions on the share itself. Special format: Every permission is seperated by a comma and the identity and the access right are seperated by a |
            Default: Everyone|FullControl
            Possible Permissions: Read, Change, FullControl, Deny-FullControl
            Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, <NETBIOSDOMAINNAME>\<sAMAccountName> (domain objects)

        .PARAMETER ABE
            Access based enumaration, can be Enabled or Disabled (default)

        .PARAMETER CachingMode
            Offline Folder configuration, can be Manual (default), "None", "Documents" (all documents are automaticaly offline available), "Programs" ("Performance option", all files are automaticaly offline available)

        .PARAMETER MaxUses
            Allowed connections to the share. Default is -1 that equals maximum

        .NOTES
            Name: Set-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 17.05.2018

        .EXAMPLE
            Set-NetShare -Server 'srv1234' -Name 'TestShare' -Description "A test share" -ABE Enabled -CachingMode None -MaxUses 50 -Permissions "DOMAINNAME\Domain Admins|FullControl,Everyone|Change,BUILTIN\Administrators|FullControl"

            Description
            -----------
            Sets the given options and permissions a server named srv1234 on the share named TestShare
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Name,

        [Parameter(Position=2,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Description,

        [Parameter(Position=3,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Permissions,

        [Parameter(Position=4,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Disabled", "Enabled", IgnoreCase = $true)]  # FolderEnumerationMode AccessBased, Unrestricted
        [string]$ABE,

        [Parameter(Position=5,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Manual", "None", "Documents", "Programs", IgnoreCase = $true)]
        [string]$CachingMode,

        [Parameter(Position=6,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Int]$MaxUses

    )
    Begin {
        # Read all existing share informations

        # We want to query the 502 data first
        $bufptr502 = [IntPtr]::Zero
        $struct502 = New-Object Netapi+SHARE_INFO_502
        $return = [Netapi]::NetShareGetInfo($Server,$Name,502,[ref]$bufptr502)

        If($return -eq 0){
            $str502 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr502,[System.Type]$struct502.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo for $Name on $Server : " + (Get-LastWin32ExceptionMessage $return))
        }

        # Now read the flags
        $bufptr1005 = [IntPtr]::Zero
        $struct1005 = New-Object Netapi+SHARE_INFO_1005
        $return = [Netapi]::NetShareGetInfo($Server,$Name,1005,[ref]$bufptr1005)

        If($return -eq 0){
            $str1005 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr1005,[System.Type]$struct1005.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo 1005 for $Name on $Server : " + (Get-LastWin32ExceptionMessage $return))
        }
        $ShareFlags = $str1005.shi1005_flags

        # Prepare for modifications
        $Write502 = $False
        $Write1005 = $False
        $paramerror = 0

        # Check for changes in the 502 structure
        If($PSBoundParameters.ContainsKey('Description')){
            If($str502.Remark -ne $Description){
                $str502.Remark = $Description
                $Write502 = $True
            }
        }

        If($PSBoundParameters.ContainsKey('MaxUses')){
            If($str502.MaxUses -ne $MaxUses){
                $str502.MaxUses = $MaxUses
                $Write502 = $True
            }
        }

        If($PSBoundParameters.ContainsKey('Permissions')){
            If($Permissions){
                # Convert and sort given permissions
                $NewACL = Convert-ACLTextToShareACL $Permissions
                $NewShareACLText = Convert-ShareACLToText $NewACL $True

                If ($str502.SecurityDescriptor -ne 0){

                    $ShareACLSSDL = Convert-SDtoSDDL $str502.SecurityDescriptor 4 # 15 or 4
                    $ShareACL = Convert-SDDLToACL -SDDLString $ShareACLSSDL
                    $ShareACLText = Convert-ShareACLToText $ShareACL $True
                }

                If($NewShareACLText -ne $ShareACLText){

                    $sddlptr = [IntPtr]::Zero
                    $sddlptr = [System.Runtime.Interopservices.Marshal]::StringToHGlobalAuto($NewACL.Sddl)

                    $SDDL_REVISION_1 = 1
                    $NewSDptr = [IntPtr]::Zero
                    $NewSDsize = [IntPtr]::Zero
                    $return = [Netapi]::ConvertStringSecurityDescriptorToSecurityDescriptor($sddlptr,$SDDL_REVISION_1,[ref]$NewSDptr,[ref]$NewSDsize)
                    If($return -ne $True){
                        Throw ("Error during ConvertStringSecurityDescriptorToSecurityDescriptor: " + (Get-LastWin32ExceptionMessage $return))
                    }

                    $str502.SecurityDescriptor = $NewSDptr
                    $Write502 = $True
                }
	        }
        }


        # Write 502 data if changed
        If($Write502){
            $structsize = [System.Runtime.InteropServices.Marshal]::SizeOf($str502)
            [IntPtr]$bufptr = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($structsize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($str502,$bufptr,$false)

            $return = [Netapi]::NetShareSetInfo($Server,$Name,502,$bufptr,$paramerror)

            If($return -ne 0){
                Throw ("Error during NetShareSetInfo 502: " + (Get-LastWin32ExceptionMessage $return))
            }
        }


        # Check for changes in the 1005 flags
        If($PSBoundParameters.ContainsKey('ABE')){
            If($ShareFlags -band [Netapi]::FLAGS_ACCESS_BASED_DIRECTORY_ENUM -AND $ABE -eq "Disabled"){
                $ShareFlags = $ShareFlags -bxor [Netapi]::FLAGS_ACCESS_BASED_DIRECTORY_ENUM
                $Write1005 = $True
            }
            If(!($ShareFlags -band [Netapi]::FLAGS_ACCESS_BASED_DIRECTORY_ENUM) -AND $ABE -eq "Enabled"){
                $ShareFlags = $ShareFlags -bor [Netapi]::FLAGS_ACCESS_BASED_DIRECTORY_ENUM
                $Write1005 = $True
            }
        }

        If($PSBoundParameters.ContainsKey('CachingMode')){
            $NewCachingFlags = [Netapi+CacheType]::($Cachingmode).value__
            If (($ShareFlags -band 0x0030) -ne $NewCachingFlags){
                $ShareFlags = $ShareFlags -bxor ($ShareFlags -band 0x0030) -bor $NewCachingFlags
                $Write1005 = $True
            }
        }

        # Write 1005 data if changed
        If($Write1005){
            $str1005.shi1005_flags = $ShareFlags
            $structsize = [System.Runtime.InteropServices.Marshal]::SizeOf($str1005)
            [IntPtr]$bufptr = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($structsize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($str1005,$bufptr,$false)

            $return = [Netapi]::NetShareSetInfo($Server,$Name,1005,$bufptr,$paramerror)

            [Netapi]::NetApiBufferFree($bufptr) | Out-Null

            If($return -ne 0){
                Throw ("Error during NetShareSetInfo 1005: " + (Get-LastWin32ExceptionMessage $return))
            }
        }

        # Cleanup memory
        [Netapi]::NetApiBufferFree($bufptr502) | Out-Null
        [Netapi]::NetApiBufferFree($bufptr1005) | Out-Null

    }
}

Function Redo-NetShare{
    <#
        .SYNOPSIS
            Creates a network file share local or on a remote computer. If a share with the same name already exists it will be modified if needed

        .DESCRIPTION
            Creates or modify a network share
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Name
            Name of the share

        .PARAMETER Path
            Local disk path to share

        .PARAMETER Description
            The description/remark of the share

        .PARAMETER Permissions
            Permissions on the share itself. Special format: Every permission is seperated by a comma and the identity and the access right are seperated by a |
            Default: Everyone|FullControl
            Possible Permissions: Read, Change, FullControl, Deny-FullControl
            Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, <NETBIOSDOMAINNAME>\<sAMAccountName> (domain objects)

        .PARAMETER ABE
            Access based enumaration, can be Enabled or Disabled (default)

        .PARAMETER CachingMode
            Offline Folder configuration, can be Manual (default), "None", "Documents" (all documents are automaticaly offline available), "Programs" ("Performance option", all files are automaticaly offline available)

        .PARAMETER MaxUses
            Allowed connections to the share. Default is -1 that equals maximum


        .NOTES
            Name: Redo-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 01.12.2018

        .EXAMPLE
            Redo-NetShare -Server 'srv1234' -Name 'TestShare' -Path 'D:\Data'

            Description
            -----------
            Shares the path D:\Data on the server named srv1234 as TestShare. If a share with the same name on the same server exists, it will be changed or recreated
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Name,

        [Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path,

        [Parameter(Position=3,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Description,

        [Parameter(Position=4,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Permissions,  # = "Everyone|FullControl"

        [Parameter(Position=5,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Disabled", "Enabled", IgnoreCase = $true)]  # FolderEnumerationMode AccessBased, Unrestricted
        [string]$ABE = "Disabled",

        [Parameter(Position=6,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Manual", "None", "Documents", "Programs", IgnoreCase = $true)]
        [string]$CachingMode = "Manual",

        [Parameter(Position=7,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Int]$MaxUses = -1

    )
    Begin {

        Try{
            $ExistingShare = Get-NetShare -Server $Server -Name $Name
        } Catch {
            $error.clear()
        }

        If($ExistingShare){
            # Preserve values if not changed
            If(-Not $PSBoundParameters.ContainsKey('Description')){
                $Description = $ExistingShare.Description
            }
            If(-Not $PSBoundParameters.ContainsKey('Permissions')){
                $Permissions = $ExistingShare.ShareACLText
            }
            If(-Not $PSBoundParameters.ContainsKey('ABE')){
                $ABE = $ExistingShare.ABE
            }
            If(-Not $PSBoundParameters.ContainsKey('CachingMode')){
                $CachingMode = $ExistingShare.CachingMode
            }
            If(-Not $PSBoundParameters.ContainsKey('MaxUses')){
                $MaxUses = $ExistingShare.ConcurrentUserLimit
            }

            If($ExistingShare.Path -eq $Path){
                # Just modify Settings
                $return = Set-NetShare -Server $Server -Name $Name -Description $Description -Permissions $Permissions -ABE $ABE -CachingMode $CachingMode -MaxUses $MaxUses
            } Else {
                # Path is different, so the share must be erased and recreated
                $return = Remove-NetShare -Server $Server -Name $Name
                $return = New-NetShare -Server $Server -Name $Name -Path $Path -Description $Description -Permissions $Permissions -ABE $ABE -CachingMode $CachingMode -MaxUses $MaxUses
            }

        } Else {
            $return = New-NetShare -Server $Server -Name $Name -Path $Path -Description $Description -Permissions $Permissions -ABE $ABE -CachingMode $CachingMode -MaxUses $MaxUses
        }
        $return = $return
    }
}

Function Remove-NetShare{
    <#
        .SYNOPSIS
            Deletes a network file share local or on a remote computer

        .DESCRIPTION
            Removes / stops a share localy or on a remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Name
            Name of the share

        .NOTES
            Name: Remove-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 18.05.2018

        .EXAMPLE
            Remove-NetShare -Server 'srv1234' -Name 'TestShare'

            Description
            -----------
            Deletes the share named TestShare on the server named srv1234
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Name
    )
    Begin {
        $reserved = 0
        $return = [Netapi]::NetShareDel($Server,$Name,$reserved)

        If($return -ne 0){
            Throw ("Error during NetShareDel for $Name on $Server : " + (Get-LastWin32ExceptionMessage $return))
        }
    }
}


Function Get-NetShareDiskspace{
    <#
        .SYNOPSIS
            Retrieves disk space infos from the specified network share

        .DESCRIPTION
            Retrieves the availabe space for the calling user and the total free space on the disk and the total disk space

        .PARAMETER Name
            Name of the share

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Unit
            Unit of the returned sizes, if not specified the vaules are in bytes, possible units are "KB","MB","GB" or "TB"

        .NOTES
            Name: Get-NetShareDiskspace
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 01.12.2018

        .EXAMPLE
            Get-NetShareDiskspace -Name 'TestShare' -Server 'srv1234' -Unit GB

            Description
            -----------
            Gets the disk space information of the share named "TestShare" of a remote server
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Name,

        [Parameter(Position=1,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=2,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("KB","MB","GB","TB",IgnoreCase = $true)]
        [string]$Unit
    )
    Begin {
        $Path = '\\' + $Server + '\' + $Name

   		switch($Unit){
			"KB" {$UnitDevider = 1kb;break}
			"MB" {$UnitDevider = 1mb;break}
			"GB" {$UnitDevider = 1gb;break}
			"TB" {$UnitDevider = 1tb;break}
			default {$UnitDevider = 1;break}
		}

		$UserFree = New-Object System.UInt64
		$DiskFree = New-Object System.UInt64
		$DiskSize = New-Object System.UInt64

        $result = [Netapi]::GetDiskFreeSpaceEx($Path,([ref]$UserFree),([ref]$DiskSize),([ref]$DiskFree))

        If(!$result){
            $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Throw ("Error during GetDiskFreeSpaceEx for path $Path : " + $LastError)
        }

        # Define output object
        $ShareDiskInfo = New-Object -TypeName PSObject

        $ShareDiskInfo | Add-Member Server      $Server
        $ShareDiskInfo | Add-Member Name        $Name
        $ShareDiskInfo | Add-Member Path        $Path
        $ShareDiskInfo | Add-Member UserFree    ([UInt64]($UserFree/$UnitDevider))
        $ShareDiskInfo | Add-Member DiskFree    ([UInt64]($DiskFree/$UnitDevider))
        $ShareDiskInfo | Add-Member DiskSize    ([UInt64]($DiskSize/$UnitDevider))

        $ShareDiskInfo

    }
}


Function Get-NetSessions{
    <#
        .SYNOPSIS
            Retrieves all open server sessions from a local or remote computer

        .DESCRIPTION
            Retrieves all usefull session informations from a local or remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Level
            NetSessionEnum info level. Defaults 502, but you can use 1 for compatibility reasons

        .NOTES
            Name: Get-NetSessions
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 11.05.2018
                1.1 //Add level option 01.12.2018

            OUTPUT : Array of objects with Username,Client,ClientIP,Opens (open files),TimeTS (as timespan),Time (as string),Connected (as DateTime),IdleTS (as timespan),Idle (as string),IdleSince (as DateTime),ConnectionType


        .EXAMPLE
            Get-NetSessions -Server 'srv1234'

            Description
            -----------
            Gets the information of all shares of a remote server
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),

        [Parameter(Position=1,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateSet(502,10,1,0)]
        [Int]$Level = 502
    )
    Begin {
        If($Level -eq 0){
            $struct = New-Object netapi+SESSION_INFO_0
        }
        If($Level -eq 1){
            $struct = New-Object netapi+SESSION_INFO_1
        }
        If($Level -eq 10){
            $struct = New-Object netapi+SESSION_INFO_10
        }
        If($Level -eq 502){
            $struct = New-Object netapi+SESSION_INFO_502
        }

	    $buffer = 0
	    $entries = 0
	    $total = 0
	    $handle = 0
        $now = Get-Date
	    $Sessions = @()
        $client = $null # for NetAPP compatibility
        $user = $null # for NetAPP compatibility
        $ReadFinished = $False

        While($ReadFinished -eq $False){

            $return = [Netapi]::NetSessionEnum($server, $client, $user, $level,[ref]$buffer, -1,[ref]$entries, [ref]$total,[ref]$handle)

            If($return -ne 0 -and $return -ne 234){
                Throw ("Error during NetSessionEnum: " + (Get-LastWin32ExceptionMessage $return))
            }

            If($entries -eq $total -and $return -eq 0){$ReadFinished = $True}

            $offset = $buffer.ToInt64()
            $increment = [System.Runtime.Interopservices.Marshal]::SizeOf([System.Type]$struct.GetType())

            for ($i = 0; $i -lt $entries; $i++)
            {
                $ptr = New-Object system.Intptr -ArgumentList $offset
                $Session = [system.runtime.interopservices.marshal]::PtrToStructure($ptr, [System.Type]$struct.GetType())

                $offset = $ptr.ToInt64()
                $offset += $increment

                $ClientIP = $session.Name
                # Resolve hostname
                $Clientname = Get-DNSGet-DNSReverseLookup $Session.Name

                $TimeTS = New-TimeSpan -Seconds $Session.Time
                $Time = [String]([Int]$TimeTS.TotalHours) + ":" + [String]($TimeTS.Minutes)
                $Connected = ($Now - $TimeTS)       # .ToString('yyyy-MM-dd HH:mm')

                $IdleTS = New-TimeSpan -Seconds $Session.IdleTime
                $Idle = [String]([Int]$IdleTS.TotalHours) + ":" + [String]($IdleTS.Minutes)
                $IdleSince = ($Now - $IdleTS)       # .ToString('yyyy-MM-dd HH:mm')

                If($Level -eq 1){
                    $Sessions += $Session | Select-Object -Property Username,@{n='Client';e={$Clientname}},@{n='ClientIP';e={$ClientIP}},@{n='Opens';e={$_.NumOpens}},@{n='TimeTS';e={$TimeTS}},@{n='Time';e={$Time}},@{n='Connected';e={$Connected}},@{n='IdleTS';e={$IdleTS}},@{n='Idle';e={$Idle}},@{n='IdleSince';e={$IdleSince}}
                } else {
                    $Sessions += $Session | Select-Object -Property Username,@{n='Client';e={$Clientname}},@{n='ClientIP';e={$ClientIP}},@{n='Opens';e={$_.NumOpens}},@{n='TimeTS';e={$TimeTS}},@{n='Time';e={$Time}},@{n='Connected';e={$Connected}},@{n='IdleTS';e={$IdleTS}},@{n='Idle';e={$Idle}},@{n='IdleSince';e={$IdleSince}},ConnectionType
                }
            }
        }

	    $Sessions | Sort-Object Username,Client

        # Cleanup memory
        [Netapi]::NetApiBufferFree($buffer) | Out-Null
    }

}


Function Close-NetSession{
    <#
        .SYNOPSIS
            Force-closes an open session on a server

        .DESCRIPTION
            Closes an open session on a local or remote computer by specifying user AND client IP
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER User
            The user that sessions should be ended on the server

        .PARAMETER ClientIP
            The client that sessions should be ended on the server (IP Address)

        .NOTES
            Name: Close-NetSession
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 23.03.2020

        .EXAMPLE
            Close-NetSession -Server 'srv1234' -User 'TestUser' -ClientIP '11.22.33.44'

            Description
            -----------
            Closes the open session(s) of user "TestUser" comming from IP 11.22.33.44 on server srv1234
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),
        [Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$User,
        [Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$ClientIP
    )
    Begin {
        If($ClientIP){
            $ClientIPUNC = "\\" + $ClientIP
        }

        $return = [Netapi]::NetSessionDel($Server,$ClientIPUNC,$User)

        If($return -ne 0){
            Throw ("Error during NetSessionDel for user $User and client $ClientIP on $Server : " + (Get-LastWin32ExceptionMessage $return))
        }
    }
}


Function Get-NetOpenFiles{
    <#
        .SYNOPSIS
            Retrieves all open files from a local or remote computer

        .DESCRIPTION
            Retrieves all usefull informations about open files from a local or remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Path
            Beginning (left part) of a server local path to filter the results, if left undefined no path filter is applied

        .PARAMETER User
            Username to filter the results, if left undefined all open files are listed, if left undefined no user filter is applied

        .PARAMETER WithID
            If this switch is set a FileID will also be returned

        .NOTES
            Name: Get-NetOpenFiles
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 11.05.2018
                1.1 //Added user filter and output of the FileID 23.03.2020

            OUTPUT : Array of objects with Path, Username, Access Rights, Locks and optional the FileID


        .EXAMPLE
            Get-NetOpenFiles -Server 'srv1234' -Path "C:\vol_fs_cifs_srv001234_001\data\Progs"

            Description
            -----------
            Gets the information of open files in a specific folder
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),
        [Parameter(Position=1,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path = $Null,
        [Parameter(Position=2,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$User = $Null,
        [Parameter(Position=3,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [switch]$WithID
    )
    Begin {
        $level = 3
        $struct = New-Object netapi+FILE_INFO_3

	    $buffer = 0
	    $entries = 0
	    $total = 0
	    $handle = 0
	    $Files = @()
        # $user = $null # for NetAPP compatibility
        $ReadFinished = $False

        While($ReadFinished -eq $False){

            $return = [Netapi]::NetFileEnum($server,$path,$null,$level,[ref]$buffer,-1,[ref]$entries, [ref]$total,[ref]$handle)

            If($return -ne 0 -and $return -ne 234){
                Throw ("Error during NetFileEnum: " + (Get-LastWin32ExceptionMessage $return))
            }

            If($entries -eq $total -and $return -eq 0){$ReadFinished = $True}

            $offset = $buffer.ToInt64()
            $increment = [System.Runtime.Interopservices.Marshal]::SizeOf([System.Type]$struct.GetType())

            for ($i = 0; $i -lt $entries; $i++)
            {
                $ptr = New-Object system.Intptr -ArgumentList $offset
                $File = [system.runtime.interopservices.marshal]::PtrToStructure($ptr, [System.Type]$struct.GetType())

                $offset = $ptr.ToInt64()
                $offset += $increment

                Switch ($File.Permissions){
                    1 { $Access = "Read" }
                    2 { $Access = "Write" }
                    3 { $Access = "Write" }
                    4 { $Access = "Create" }

                    default { $Access = "" }
                }

                If($User){
                    If($File.User -ine $User){
                        Continue
                    }
                }

                If($WithID){
                    $Files += $File | Select-Object Path,User,@{n='Access';e={$Access}},@{n='Locks';e={$File.NumLocks}},@{n='FileID';e={$File.FileID}}
                } else {
                    $Files += $File | Select-Object Path,User,@{n='Access';e={$Access}},@{n='Locks';e={$File.NumLocks}}
                }
            }
        }

	    $Files | Sort-Object Path,User

        # Cleanup memory
        [Netapi]::NetApiBufferFree($buffer) | Out-Null

    }
}


Function Close-NetOpenFiles{
    <#
        .SYNOPSIS
            Force-closes an open path or file

        .DESCRIPTION
            Closes an open file or folder from a local or remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER FileID
            FileID to close (Get the FileID by using Get-NetOpenFiles with the option -WithID)

        .NOTES
            Name: Close-NetOpenFiles
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 23.03.2020

        .EXAMPLE
            Close-NetOpenFiles -Server 'srv1234' -FileID 2751

            Description
            -----------
            Closes the open file handle with the ID 2721 on server srv1234
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower(),
        [Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [UInt32]$FileID
    )
    Begin {
        $return = [Netapi]::NetFileClose($Server,$FileID)

        If($return -ne 0){
            Throw ("Error during NetFileClose for $FileID on $Server : " + (Get-LastWin32ExceptionMessage $return))
        }
    }
}

Function Get-SnapshotPath{
    <#
        .SYNOPSIS
            Get all VSS snapshot paths for the path specified.

        .DESCRIPTION
            Scans the UNC or Local path for a list of VSS snapshots and the path that
            can be used to reach these files.

        .PARAMETER Path
            The UNC or mapped drive path to search.

        .NOTES
            Name: Get-SnapshotPath
            Author: Jordan Borean (@jborean93) <jborean93@gmail.com>
            OUTPUT : Array of strings with the full snapshot paths

        .EXAMPLE
            Get-SnapshotPath -Path \\server\share
            Get-SnapshotPath -Path C:\Windows
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    If (-not (Test-Path -LiteralPath $Path)) {
        Write-Error -Message "Could not find UNC path '$Path'" -Category ObjectNotFound
        return
    }

    # Create a SafeFileHandle of the path specified and make sure it is valid
    $Handle = [Win32.NativeMethods]::CreateFileW(
        $Path,
        [System.Security.AccessControl.FileSystemRights]"ListDirectory, ReadAttributes, Synchronize",
        [System.IO.FileShare]::ReadWrite,
        [System.IntPtr]::Zero,
        [System.IO.FileMode]::Open,
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        [System.IntPtr]::Zero
    )
    if ($Handle.IsInvalid) {
        $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Msg = Get-LastWin32ExceptionMessage -ErrorCode $LastError
        Write-Error -Message "CreateFileW($Path) failed - $Msg"
        return
    }

    try {
        # Set the initial buffer size to the size of NT_Trans_Data + 2 chars. We do this so we can get the actual buffer
        # size that is contained in the NT_Trans_Data struct. A char is 2 bytes (UTF-16) and we expect 2 of them
        $TransDataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][Win32.NativeHelpers+NT_Trans_Data])
        $BufferSize = $TransDataSize + 4

        # Invoke NtFsControlFile at least once to get the number of snapshots and total size of the NT_Trans_Data
        # buffer. If there are 1 or more snapshots we invoke it again to get the actual snapshot strings
        Invoke-EnumerateSnapshots -Handle $Handle -BufferSize $BufferSize -ScriptBlock {
            $TransactionData = $args[1]

            if ($TransactionData.NumberOfSnapShots -gt 0) {
                # There are snapshots to retrieve, reset the buffer size to the original size + the return array size
                $NewBufferSize = $BufferSize + $TransactionData.SnapShotArraySize

                # Invoke NtFsControlFile with the larger buffer size but now we can parse the NT_Trans_Data
                Invoke-EnumerateSnapshots -Handle $Handle -BufferSize $NewBufferSize -ScriptBlock {
                    $OutBuffer = $args[0]
                    $TransactionData = $args[1]

                    $SnapshotPtr = [System.IntPtr]::Add($OutBuffer, $TransDataSize)
                    $SnapshotString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($SnapshotPtr,
                        $TransactionData.SnapShotArraySize / 2)

                    Write-Output -InputObject ($SnapshotString.Split([char[]]@("`0"), [System.StringSplitOptions]::RemoveEmptyEntries))
                }
            }
        } | ForEach-Object -Process { Join-Path -Path $Path -ChildPath $_ }
    } finally {
        # Technically not needed as a SafeFileHandle will auto dispose once the GC is called but it's good to be
        # explicit about these things
        $Handle.Dispose()
    }
}

Function Get-SnapshotItems{
    <#
        .SYNOPSIS
            Retrieves all previous versions of a folder or file

        .DESCRIPTION
            Retrieves file or folder items of previous versions of a given object including a timestamp when the snapshot was taken

        .PARAMETER Path
            The UNC or mapped drive path to search.

        .NOTES
            Name: Get-SnapshotItems
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 20.03.2021

            OUTPUT : Array of file or folder objects with additional value SnapshotCreationTime


        .EXAMPLE
            Get-SnapshotItems -Path "\\FileServer001\data\Org"

            Description
            -----------
            Gets a list of available snapshots of the folder
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path
    )
    Begin {
        $SnapshotsFolders = @()

        # Check if the given path item exists now
        Try{
            $SourceItem = Get-Item -LiteralPath $Path -ErrorAction Stop
            $SearchMode = $False

            # Check if path given is a folder or a file that makes search more complicated
            IF($SourceItem.PSIsContainer){
                $FolderPath = $SourceItem.FullName
                $SourceFile = $NULL
            } Else {
                # Prepare file search
                $FolderPath = Split-Path ($SourceItem.FullName) -Parent
                $SourceFile = $SourceItem
                $LastVersionDate = $SourceItem.LastWriteTimeUtc
            }
        } Catch {
            $FolderPath = $Path
            $SearchMode = $True

            #Searching existing parent folder
            While(!$SearchPath){
                $FolderPath = Split-Path $FolderPath -Parent
                $SourceItem = Get-Item -LiteralPath $FolderPath -ErrorAction SilentlyContinue

                If($SourceItem){
                    $SearchPath = $Path.Replace($FolderPath,'')
                }
            }
        }

        # Use Get-SnapshotPath to get full path of existing Snapshots
        $SnapPaths = Get-SnapshotPath -Path $FolderPath

        # Get item for each result
        ForEach($SnapPath in $SnapPaths){
            $FolderObj = Get-Item -LiteralPath $SnapPath
            $SnapshotDateTime = [datetime]::parseexact($FolderObj.Name, '@GMT-yyyy.MM.dd-HH.mm.ss', $null)
            $SnapshotsFolders += $FolderObj | Select-Object *,@{n='SnapshotCreationTime';e={$SnapshotDateTime}}
        }

        # Search mode needs to check each snapshot for given path
        If($SearchMode){
            $TempResult = @()

            # look for search path or file in every snapshot of this share
            ForEach($SnapshotsFolder in $SnapshotsFolders){
                $TestItem = Get-Item -LiteralPath ($SnapshotsFolder.FullName + $SearchPath) -ErrorAction SilentlyContinue

                IF($TestItem){
                    IF($TestItem.PSIsContainer){
                        $TempResult += $TestItem | Select-Object *,@{n='SnapshotCreationTime';e={$SnapshotsFolder.SnapshotCreationTime}}
                    } Else {
                        $TempResult += Get-Item -LiteralPath (Split-Path ($SnapshotsFolder.FullName + $SearchPath) -Parent) -ErrorAction SilentlyContinue | Select-Object *,@{n='SnapshotCreationTime';e={$SnapshotsFolder.SnapshotCreationTime}}
                        $SourceFile = $TestItem
                    }
                }
            }
            $SnapshotsFolders = $TempResult
        }

        # If the item of intrest is or used to be a file ...
        If($SourceFile){

            # Check every file version
            ForEach($SnapshotsFolder in $SnapshotsFolders){
                Try{
                    $TestFile = Get-Item -LiteralPath ($SnapshotsFolder.FullName + "\" + $SourceFile.Name) -ErrorAction SilentlyContinue
                } Catch {
                    $error.clear()
                    Continue
                }

                # Compare Modify dates
                If($LastVersionDate -ne $TestFile.LastWriteTimeUtc){
                    $TestFile | Select-Object *,@{n='SnapshotCreationTime';e={$SnapshotsFolder.SnapshotCreationTime}}
                    $LastVersionDate = $TestFile.LastWriteTimeUtc
                }
            }

        } Else {
            $SnapshotsFolders
        }
    }
}
