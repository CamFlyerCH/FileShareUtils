Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;

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

    [DllImport("Netapi32.dll", SetLastError=true)]
    public static extern int NetShareDel(
        [MarshalAs(UnmanagedType.LPWStr)] string serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string netName,
        Int32 reserved);
 
    }
"@ 

# Helper - Functions ===========================================================================

Function NetAPIReturnHelp($CallReturn){
    ([ComponentModel.Win32Exception][Int32]$CallReturn).Message
    #net helpmsg $CallReturn
}

Function ReverseLookup{
    Param(
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$IP
    )
    Process {
        Trap{$IP;continue} 
        [System.Net.Dns]::GetHostEntry($IP).HostName
    }
}

Function ShareACLToText($ShareACL,$SortACL){
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

Function ACLTextToShareACL($UnsortedACLText){
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

Function SDtoSDDL($ptr2SD,$SECURITY_INFORMATION){
    #OWNER_SECURITY_INFORMATION	1	der Eigentümer wird konvertiert
    #GROUP_SECURITY_INFORMATION	2	die primäre Gruppe wird konvertiert
    #DACL_SECURITY_INFORMATION	4	die DACL Zugriffskontrollliste wird konvertiert
    #SACL_SECURITY_INFORMATION	8	die System Zugriffskontrollliste wird konvertiert
    #LABEL_SECURITY_INFORMATION	16	die Mandantory Zugriffskontrolleinträge werden konvertiert
    #$SECURITY_INFORMATION = 4
    $SDDL_REVISION_1 = 1

	$return = [Netapi]::IsValidSecurityDescriptor($ptr2SD)
    #Write-Host $return

    $sddlptr = [IntPtr]::Zero
    $sddllength = [IntPtr]::Zero
	$return = [Netapi]::ConvertSecurityDescriptorToStringSecurityDescriptor($ptr2SD,$SDDL_REVISION_1,$SECURITY_INFORMATION,[ref]$sddlptr,[ref]$sddllength)
    If($return -ne $True){
        Throw ("Error during ConvertSecurityDescriptorToStringSecurityDescriptor: " + (NetAPIReturnHelp $return))
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

        .NOTES
            Name: Get-NetShares
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 10.05.2018

        .OUTPUT
            Object with .......


        .EXAMPLE
            Get-NetShares -Server 'srv1234'

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
        # We want to query the 502 datas
	    $buffer = 0
	    $entries = 0
	    $total = 0
	    $handle = 0
        $Shares = @()
        $struct = New-Object Netapi+SHARE_INFO_502
        $return = [Netapi]::NetShareEnum($Server,502,[ref]$buffer,-1,[ref]$entries, [ref]$total,[ref]$handle) 


        If($return -ne 0){
            Write-Output ([ComponentModel.Win32Exception][Int32]$ret).Message
            Throw ("Error during NetShareEnum: " + (NetAPIReturnHelp $return))
        }

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

        $Shares | Sort-Object Path

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

        .OUTPUT
            Object with .......


        .EXAMPLE
            Get-NetShare -Name 'TestShare' -Server 'srv1234'

            Description
            -----------
            Gets the information of the share named "TestShare" of a remote server
    #>
	[CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [string]$SpecifiedName,

        [Parameter(Position=1,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Server = ($env:computername).toLower()
    )
    Begin {
        # We want to query the 502 data first
        $bufptr = [IntPtr]::Zero
        $struct = New-Object Netapi+SHARE_INFO_502
        $return = [Netapi]::NetShareGetInfo($Server,$SpecifiedName,502,[ref]$bufptr)

        If($return -eq 0){
            $str502 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr,[System.Type]$struct.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo for $SpecifiedName : " + (NetAPIReturnHelp $return))
        }

        # Now read the flags
        $bufptr = [IntPtr]::Zero
        $struct = New-Object Netapi+SHARE_INFO_1005
        $return = [Netapi]::NetShareGetInfo($Server,$SpecifiedName,1005,[ref]$bufptr)

        If($return -eq 0){
            $str1005 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr,[System.Type]$struct.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo 1005: " + (NetAPIReturnHelp $return))
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
            $ShareACLSSDL = SDtoSDDL $str502.SecurityDescriptor 4 # 15 or 4
            $ShareACL = Convert-SDDLToACL -SDDLString $ShareACLSSDL
            #$ShareACLText = $ShareACL.AccessToString
            $ShareACLText = ShareACLToText $ShareACL $True

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

        .OUTPUT
            Object with .......


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
            Permissions on the share itself. Speical format: Every permission is seperated by a comma and the identity and the access right are seperated by a |
            Default: Everyone|FullControl
            Possible Permissions: Read, Change, FullControl, Deny-FullControl
            Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, <NETBIOSDOMAINNAME>\<sAMAccountName> (domain objects)

        .PARAMETER ABE
            Access based enumaration, can be Enabled or Disabled (default)

        .PARAMETER CachingMode
            Offline Folder configuration, can be Manual (default), "None", "Documents" (all documents are automaticaly offline available), "Programs" ("Performance option", all files are automaticaly offline available)

        .PARAMETER MaxUses
            Allowed connections to the share. Default is -1 that equals Maximum


        .NOTES
            Name: New-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 17.05.2018

        .OUTPUT
            Nothing


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

        If($return -ne 0){
            #Write-Output ([ComponentModel.Win32Exception][Int32]$return).Message
            Throw ("Error during NetShareAdd: " + (NetAPIReturnHelp $return))
        }

        Set-NetShare -Server $Server -Name $Name -Description $Description -Permissions $Permissions -ABE $ABE -CachingMode $CachingMode -MaxUses $MaxUses

    }
}

Function Set-NetShare{
    <#
        .SYNOPSIS
            Changes options on a network file share local or on a remote computer

        .DESCRIPTION
            Can modify all changeabla options of a file share local or on a remote computer
            by using the NetAPI32.dll (without WMI)

        .PARAMETER Server
            Computername on the network, local if left blank

        .PARAMETER Name
            Name of the share

        .PARAMETER Description
            The description/remark of the share

        .PARAMETER Permissions
            Permissions on the share itself. Speical format: Every permission is seperated by a comma and the identity and the access right are seperated by a |
            Default: Everyone|FullControl
            Possible Permissions: Read, Change, FullControl, Deny-FullControl
            Possible Identities: Everyone, BUILTIN\Administrators, BUILTIN\Users, BUILTIN\xxxxx (server local users or groups), DOMAIN\UserName, ADCORP\GroupName, <NETBIOSDOMAINNAME>\<sAMAccountName> (domain objects)

        .PARAMETER ABE
            Access based enumaration, can be Enabled or Disabled (default)

        .PARAMETER CachingMode
            Offline Folder configuration, can be Manual (default), "None", "Documents" (all documents are automaticaly offline available), "Programs" ("Performance option", all files are automaticaly offline available)

        .PARAMETER MaxUses
            Allowed connections to the share. Default is -1 that equals Maximum

        .NOTES
            Name: Set-NetShare
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 17.05.2018

        .OUTPUT
            Nothing


        .EXAMPLE
            New-NetShare -Server 'srv1234' -Name 'TestShare' -Description "A test share" -ABE Enabled -CachingMode None -MaxUses 50 -Permissions "DOMAINNAME\Domain Admins|FullControl,Everyone|Change,BUILTIN\Administrators|FullControl"

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
            Throw ("Error during NetShareGetInfo for $Name on $Server : " + (NetAPIReturnHelp $return))
        }

        # Now read the flags
        $bufptr1005 = [IntPtr]::Zero
        $struct1005 = New-Object Netapi+SHARE_INFO_1005
        $return = [Netapi]::NetShareGetInfo($Server,$Name,1005,[ref]$bufptr1005)

        If($return -eq 0){
            $str1005 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufptr1005,[System.Type]$struct1005.GetType())
        } Else {
            Throw ("Error during NetShareGetInfo 1005 for $Name on $Server : " + (NetAPIReturnHelp $return))
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
                # Cenvert and sort given permissions
                $NewACL = ACLTextToShareACL $Permissions
                $NewShareACLText = ShareACLToText $NewACL $True
                
                If ($str502.SecurityDescriptor -ne 0){

                    $ShareACLSSDL = SDtoSDDL $str502.SecurityDescriptor 4 # 15 or 4
                    $ShareACL = Convert-SDDLToACL -SDDLString $ShareACLSSDL
                    $ShareACLText = ShareACLToText $ShareACL $True
                }

                If($NewShareACLText -ne $ShareACLText){

                    $sddlptr = [IntPtr]::Zero
                    $sddlptr = [System.Runtime.Interopservices.Marshal]::StringToHGlobalAuto($NewACL.Sddl)

                    $SDDL_REVISION_1 = 1
                    $NewSDptr = [IntPtr]::Zero
                    $NewSDsize = [IntPtr]::Zero
                    $return = [Netapi]::ConvertStringSecurityDescriptorToSecurityDescriptor($sddlptr,$SDDL_REVISION_1,[ref]$NewSDptr,[ref]$NewSDsize)
                    If($return -ne $True){
                        Throw ("Error during ConvertStringSecurityDescriptorToSecurityDescriptor: " + (NetAPIReturnHelp $return))
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
                #Write-Output ([ComponentModel.Win32Exception][Int32]$return).Message
                Throw ("Error during NetShareSetInfo 502: " + (NetAPIReturnHelp $return))
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

            If($return -ne 0){
                #Write-Output ([ComponentModel.Win32Exception][Int32]$return).Message
                Throw ("Error during NetShareSetInfo 1005: " + (NetAPIReturnHelp $return))
            }
        }

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

        .OUTPUT
            Nothing


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
            Throw ("Error during NetShareDel for $Name on $Server : " + (NetAPIReturnHelp $return))
        }
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

        .NOTES
            Name: Get-NetSessions
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 11.05.2018

        .OUTPUT
            Array of objects with Username,Client,Opens (open files),TimeTS (as timespan),Time (as string),Connected (as DateTime),IdleTS (as timespan),Idle (as string),IdleSince (as DateTime),ConnectionType


        .EXAMPLE
            Get-NetSessions -Server 'srv1234'

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
        # Not a option anymore, we read with level 502
        #switch ($level)
	    #{
		#    0   { $struct = New-Object netapi+SESSION_INFO_0 }
		#    1   { $struct = New-Object netapi+SESSION_INFO_1 }
		#    2   { $struct = New-Object netapi+SESSION_INFO_2 }
		#    10  { $struct = New-Object netapi+SESSION_INFO_10 }
		#    502 { $struct = New-Object netapi+SESSION_INFO_502 }
		#
		#    default
		#    {
			    $level = 502
			    $struct = New-Object netapi+SESSION_INFO_502
		#    }
	    #}

	    $buffer = 0
	    $entries = 0
	    $total = 0
	    $handle = 0
        $now = Get-Date
	    $Sessions = @()
        $client = $null # for NetAPP compatibility
        $user = $null # for NetAPP compatibility
	    $return = [Netapi]::NetSessionEnum($server, $client, $user, $level,[ref]$buffer, -1,[ref]$entries, [ref]$total,[ref]$handle)

        If($return -ne 0){
            Write-Output ([ComponentModel.Win32Exception][Int32]$ret).Message
            Throw ("Error during NetShareEnum: " + (NetAPIReturnHelp $return))
        }


		$offset = $buffer.ToInt64()
		$increment = [System.Runtime.Interopservices.Marshal]::SizeOf([System.Type]$struct.GetType())

		for ($i = 0; $i -lt $entries; $i++)
		{
	        $ptr = New-Object system.Intptr -ArgumentList $offset
	        $Session = [system.runtime.interopservices.marshal]::PtrToStructure($ptr, [System.Type]$struct.GetType())

			$offset = $ptr.ToInt64()
	        $offset += $increment

            # Resolve hostname
            $Clientname = ReverseLookup $Session.Name

            $TimeTS = New-TimeSpan -Seconds $Session.Time
            $Time = [String]([Int]$TimeTS.TotalHours) + ":" + [String]($TimeTS.Minutes)
            $Connected = ($Now - $TimeTS)       # .ToString('yyyy-MM-dd HH:mm')

            $IdleTS = New-TimeSpan -Seconds $Session.IdleTime
            $Idle = [String]([Int]$IdleTS.TotalHours) + ":" + [String]($IdleTS.Minutes)
            $IdleSince = ($Now - $IdleTS)       # .ToString('yyyy-MM-dd HH:mm')

            $Sessions += $Session | Select-Object -Property Username,@{n='Client';e={$Clientname}},@{n='Opens';e={$_.NumOpens}},@{n='TimeTS';e={$TimeTS}},@{n='Time';e={$Time}},@{n='Connected';e={$Connected}},@{n='IdleTS';e={$IdleTS}},@{n='Idle';e={$Idle}},@{n='IdleSince';e={$IdleSince}},ConnectionType 
		}


	    $Sessions = $Sessions | Sort-Object Username,Client
        $Sessions

        [Netapi]::NetApiBufferFree($buffer) | Out-Null
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
            Beginning (left part) of a server local path to filter the results, if left undefined all open files are listed

        .NOTES
            Name: Get-NetOpenFiles
            Author: Jean-Marc Ulrich
            Version History:
                1.0 //First version 11.05.2018

        .OUTPUT
            Array of objects with Username,Client,Opens (open files),TimeTS (as timespan),Time (as string),Connected (as DateTime),IdleTS (as timespan),Idle (as string),IdleSince (as DateTime),ConnectionType


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
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$Path = $Null
    )
    Begin {
        # Not a option anymore, we read with level 3
	    #switch ($level)
	    #{
		#    2   { $struct = New-Object netapi+FILE_INFO_2 }
		#    3   { $struct = New-Object netapi+FILE_INFO_3 }
		#    default
		#    {
			    $level = 3
			    $struct = New-Object netapi+FILE_INFO_3 
		#    }
	    #}

	    $buffer = 0
	    $entries = 0
	    $total = 0
	    $handle = 0
	    $Files = @()
        $user = $null # for NetAPP compatibility
	    $return = [Netapi]::NetFileEnum($server,$path,$user,$level,[ref]$buffer,-1,[ref]$entries, [ref]$total,[ref]$handle) 

        If($return -ne 0){
            Write-Output ([ComponentModel.Win32Exception][Int32]$ret).Message
            Throw ("Error during NetShareEnum: " + (NetAPIReturnHelp $return))
        }

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

            $Files += $File | Select-Object Path,User,@{n='Access';e={$Access}},@{n='Locks';e={$File.NumLocks}}

		}
	    $Files = $Files | Sort-Object Path,User
        $Files
    }
}

Function Get-NetStatistics
{
	[CmdletBinding()]
	param ( [Parameter(Position=0)][string]$server = "localhost", 
			[Parameter(Position=1)][string]$type="WORKSTATION")

	if ($type -eq "SERVER")
	{
		$struct = New-Object netapi+STAT_SERVER_0 
		$service = "LanmanServer"
	}
	else
	{
		$struct = New-Object netapi+STAT_WORKSTATION_0 
		$service = "LanmanWorkstation"
	}

	$buffer = 0
	$ret = [Netapi]::NetStatisticsGet($server,
									  $service,
									  0, # only level 0 is supported for now
									  0, #must be 0
								  	  [ref]$buffer)

	if (!$ret)
	{
	    $ret = [system.runtime.interopservices.marshal]::PtrToStructure($buffer, [System.Type]$struct.GetType())
		$ret
	}
	else
	{
		Write-Output ([ComponentModel.Win32Exception][Int32]$ret).Message
	}

}
