#
# Module manifest for module 'FileShareUtils'
#
# Generated by: CamFlyerCH
#
# Generated on: 18.05.2018
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'FileShareUtils.psm1'

# Version number of this module.
ModuleVersion = '1.0.23'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '71f0a8df-138e-4251-aa20-f7c0abaecda4'

# Author of this module
Author = 'Jean-Marc Ulrich (CamFlyerCH)'

# Company or vendor of this module
CompanyName = 'private'

# Copyright statement for this module
Copyright = '(c) 2020 Jean-Marc Ulrich. All rights reserved.'

# Description of the functionality provided by this module
Description = 'PowerShell module to work on file shares on Windows servers and NAS (like NetApp) WITHOUT using WMI.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = 'FileShareUtils.Format.ps1xml'

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('Get-NetShares','Get-NetShare','Get-NetFileShares','New-NetShare','Set-NetShare','Remove-NetShare','New-NetShare','Set-NetShare','Redo-NetShare','Remove-NetShare','Get-NetShareDiskspace','Get-NetSessions','Close-NetSession','Get-NetOpenFiles','Close-NetOpenFiles','Get-SnapshotPath','Get-SnapshotItems','Convert-SDDLToACL','Convert-ACLTextToShareACL','Convert-ShareACLToText','Get-DNSReverseLookup')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{
    # PSData is module packaging and gallery metadata embedded in PrivateData
    # It's for rebuilding PowerShellGet (and PoshCode) NuGet-style packages
    # We had to do this because it's the only place we're allowed to extend the manifest
    PSData = @{
        # The primary categorization of this module (from the TechNet Gallery tech tree).
        Category = "Storage"

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @("Shares","Share","SMB","ABE","netapi32","NetApp","Snapshots","Previous Versions")

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/CamFlyerCH/FileShareUtils/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/CamFlyerCH/FileShareUtils'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '1.0.23 - Add functions to enumerate snapshots / previous versions'

        # Indicates this is a pre-release/testing version of the module.
        IsPrerelease = 'False'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

