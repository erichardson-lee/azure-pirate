@{
    # Script module or binary module file associated with this manifest.
    RootModule           = 'CosmosDB.psm1'

    # Version number of this module.
    ModuleVersion        = '4.5.0'

    # Supported PSEditions
    CompatiblePSEditions = 'Core', 'Desktop'

    # ID used to uniquely identify this module
    GUID                 = '7d7aeb42-8ed9-4555-b5fd-020795a5aa01'

    # Author of this module
    Author               = 'Daniel Scott-Raynsford'

    # Company or vendor of this module
    CompanyName          = 'None'

    # Copyright statement for this module
    Copyright            = '(c) Daniel Scott-Raynsford. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'This module provides cmdlets for working with Azure Cosmos DB databases, collections, documents, attachments, offers, users, permissions, triggers, stored procedures and user defined functions.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules      = @(
        @{ ModuleName = 'Az.Accounts'; GUID = '17a2feff-488b-47f9-8729-e2cec094624c'; ModuleVersion = '1.0.0'; },
        @{ ModuleName = 'Az.Resources'; GUID = '48bb344d-4c24-441e-8ea0-589947784700'; ModuleVersion = '1.0.0'; }
    )

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess       = @(
        'types\attachments.types.ps1xml',
        'types\collections.types.ps1xml',
        'types\databases.types.ps1xml',
        'types\documents.types.ps1xml',
        'types\offers.types.ps1xml',
        'types\permissions.types.ps1xml',
        'types\storedprocedures.types.ps1xml',
        'types\triggers.types.ps1xml',
        'types\userdefinedfunctions.types.ps1xml',
        'types\users.types.ps1xml'
    )

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess     = @(
        'formats\attachments.formats.ps1xml',
        'formats\collections.formats.ps1xml',
        'formats\databases.formats.ps1xml',
        'formats\documents.formats.ps1xml',
        'formats\offers.formats.ps1xml',
        'formats\permissions.formats.ps1xml',
        'formats\storedprocedures.formats.ps1xml',
        'formats\triggers.formats.ps1xml',
        'formats\userdefinedfunctions.formats.ps1xml',
        'formats\users.formats.ps1xml'
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @('Get-CosmosDbAccount','Get-CosmosDbAccountConnectionString','Get-CosmosDbAccountMasterKey','New-CosmosDbAccount','New-CosmosDbAccountMasterKey','Remove-CosmosDbAccount','Set-CosmosDbAccount','Get-CosmosDbAttachment','Get-CosmosDbAttachmentResourcePath','New-CosmosDbAttachment','Remove-CosmosDbAttachment','Set-CosmosDbAttachment','Get-CosmosDbCollection','Get-CosmosDbCollectionResourcePath','Get-CosmosDbCollectionSize','New-CosmosDbCollection','New-CosmosDbCollectionCompositeIndexElement','New-CosmosDbCollectionExcludedPath','New-CosmosDbCollectionIncludedPath','New-CosmosDbCollectionIncludedPathIndex','New-CosmosDbCollectionIndexingPolicy','New-CosmosDbCollectionUniqueKey','New-CosmosDbCollectionUniqueKeyPolicy','Remove-CosmosDbCollection','Set-CosmosDbCollection','Get-CosmosDbDatabase','Get-CosmosDbDatabaseResourcePath','New-CosmosDbDatabase','Remove-CosmosDbDatabase','Get-CosmosDbDocument','Get-CosmosDbDocumentJson','Get-CosmosDbDocumentResourcePath','New-CosmosDbDocument','Remove-CosmosDbDocument','Set-CosmosDbDocument','Get-CosmosDbOffer','Get-CosmosDbOfferResourcePath','Set-CosmosDbOffer','Get-CosmosDbPermission','Get-CosmosDbPermissionResourcePath','New-CosmosDbPermission','Remove-CosmosDbPermission','Get-CosmosDbStoredProcedure','Get-CosmosDbStoredProcedureResourcePath','Invoke-CosmosDbStoredProcedure','New-CosmosDbStoredProcedure','Remove-CosmosDbStoredProcedure','Set-CosmosDbStoredProcedure','Get-CosmosDbTrigger','Get-CosmosDbTriggerResourcePath','New-CosmosDbTrigger','Remove-CosmosDbTrigger','Set-CosmosDbTrigger','Get-CosmosDbUserDefinedFunction','Get-CosmosDbUserDefinedFunctionResourcePath','New-CosmosDbUserDefinedFunction','Remove-CosmosDbUserDefinedFunction','Set-CosmosDbUserDefinedFunction','Get-CosmosDbUser','Get-CosmosDbUserResourcePath','New-CosmosDbUser','Remove-CosmosDbUser','Set-CosmosDbUser','Set-CosmosDbUserType','Get-CosmosDbContinuationToken','Get-CosmosDbResponseHeaderAttribute','New-CosmosDbBackoffPolicy','New-CosmosDbContext','New-CosmosDbContextToken')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = 'New-CosmosDbConnection'

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('CosmosDB', 'DocumentDb', 'Azure', 'PSEdition_Core', 'PSEdition_Desktop', 'Windows', 'Linux', 'MacOS')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/PlagueHO/CosmosDB/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/PlagueHO/CosmosDB'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = '## [4.5.0] - 2021-05-29

### Changed

- Convert build pipeline to use GitTools Azure DevOps extension tasks
  instead of deprecated GitVersion extension.
- Correct value of `Environment` parameter in context object returned
  by `New-CosmosDbContext` - Fixes [Issue #411](https://github.com/PlagueHO/CosmosDB/issues/411).
- Update `requirements.psd1` to install modules `Az.Accounts`
  2.2.8 - Fixes [Issue #415](https://github.com/PlagueHO/CosmosDB/issues/415).
- Updated `ComsosDB.cs` to add getters and setters to properties - Fixes [Issue #417](https://github.com/PlagueHO/CosmosDB/issues/417).

### Fixed

- Fix CI pipeline deployment stage to ensure correctly detects running
  in Azure DevOps organization.
- Fix CI pipeline release stage by adding Sampler GitHub tasks which
  were moved out of the main sampler module into a new module
  `Sampler.GitHubTasks` - Fixes [Issue #418](https://github.com/PlagueHO/CosmosDB/issues/418).

### Added

- Added `ReturnJson` parameter to `New-CosmosDbDocument`, `Set-CosmosDbDocument`
  and `Get-CosmosDbDocument` functions to allow return of documents that can
  not be converted to objects due to duplicate key names that only differ in
  case - Fixes [Issue #413](https://github.com/PlagueHO/CosmosDB/issues/413).

'

            Prerelease   = ''
        } # End of PSData hashtable
    } # End of PrivateData hashtable
}




