#Region './prefix.ps1' 0
<#
.EXTERNALHELP CosmosDB-help.xml
#>
#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Az.Accounts'; ModuleVersion = '1.0.0'; Guid = '17a2feff-488b-47f9-8729-e2cec094624c' }
#Requires -Modules @{ ModuleName = 'Az.Resources'; ModuleVersion = '1.0.0'; Guid = '48bb344d-4c24-441e-8ea0-589947784700' }

$script:moduleRoot = Split-Path `
    -Path $MyInvocation.MyCommand.Path `
    -Parent

# Import dependent Az modules
Import-Module -Name Az.Accounts -MinimumVersion 1.0.0 -Scope Global
Import-Module -Name Az.Resources -MinimumVersion 1.0.0 -Scope Global

#region LocalizedData
$culture = $PSUICulture

if ([System.String]::IsNullOrEmpty($culture))
{
    $culture = 'en-US'
}
else
{
    if (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath $culture)))
    {
        $culture = 'en-US'
    }
}

Import-LocalizedData `
    -BindingVariable LocalizedData `
    -Filename 'CosmosDB.strings.psd1' `
    -BaseDirectory $script:moduleRoot `
    -UICulture $culture
#endregion

#region Types
if (-not ([System.Management.Automation.PSTypeName]'CosmosDB.Context').Type)
{
    <#
        Attempt to load the classes from within the CosmosDB.dll in the
        same folder as the module. If the file doesn't exist then load
        them from the CosmosDB.cs file.

        Loading the classes from the CosmosDB.cs file requires compilation
        which currently fails in PowerShell on Azure Functions 2.0.

        See https://github.com/Azure/azure-functions-powershell-worker/issues/220
    #>
    $classDllPath = Join-Path -Path $script:moduleRoot -ChildPath 'CosmosDB.dll'

    if (Test-Path -Path $classDllPath)
    {
        Write-Verbose -Message $($LocalizedData.LoadingTypesFromDll -f $classDllPath)
        Add-Type -Path $classDllPath
    }
    else
    {
        $typeDefinitionPath = Join-Path -Path $script:moduleRoot -ChildPath 'classes\CosmosDB\CosmosDB.cs'
        Write-Verbose -Message $($LocalizedData.LoadingTypesFromCS -f $typeDefinitionPath)
        $typeDefinition = Get-Content -Path $typeDefinitionPath -Raw
        Add-Type -TypeDefinition $typeDefinition
    }
}

<#
    This type is available in PowerShell Core, but it is not available in
    Windows PowerShell. It is needed to check the exception type within the
    Invoke-CosmosDbRequest function.
#>
if (-not ([System.Management.Automation.PSTypeName]'Microsoft.PowerShell.Commands.HttpResponseException').Type)
{
    $httpResponseExceptionClassDefinition = @'
namespace Microsoft.PowerShell.Commands
{
    public class HttpResponseException : System.Net.WebException
    {
        public System.Int32 dummy;
    }
}
'@

    Add-Type -TypeDefinition $httpResponseExceptionClassDefinition
}
#endregion
#EndRegion './prefix.ps1' 87
#Region './Private/accounts/Assert-CosmosDbAccountNameValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Account name is valid.
#>
function Assert-CosmosDbAccountNameValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Name'
    )

    $matches = [regex]::Match($Name,"[A-Za-z0-9\-]{3,50}")
    if ($matches.value -ne $Name)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.AccountNameInvalid -f $Name) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/accounts/Assert-CosmosDbAccountNameValid.ps1' 33
#Region './Private/accounts/Assert-CosmosDbResourceGroupNameValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Azure Resource Group name is valid.
#>
function Assert-CosmosDbResourceGroupNameValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ResourceGroupName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'ResourceGroupName'
    )

    $matches = [regex]::Match($ResourceGroupName,"[A-Za-z0-9_\-\.]{1,90}(?<!\.)")
    if ($matches.value -ne $ResourceGroupName)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.ResourceGroupNameInvalid -f $ResourceGroupName) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/accounts/Assert-CosmosDbResourceGroupNameValid.ps1' 33
#Region './Private/userdefinedfunctions/Assert-CosmosDbUserDefinedFunctionIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB User Defined Function Id is valid.
#>
function Assert-CosmosDbUserDefinedFunctionIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.UserDefinedFunctionIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/userdefinedfunctions/Assert-CosmosDbUserDefinedFunctionIdValid.ps1' 33
#Region './Private/userdefinedfunctions/Set-CosmosDbUserDefinedFunctionType.ps1' 0
function Set-CosmosDbUserDefinedFunctionType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $UserDefinedFunction
    )

    foreach ($item in $UserDefinedFunction)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.UserDefinedFunction')
    }

    return $UserDefinedFunction
}
#EndRegion './Private/userdefinedfunctions/Set-CosmosDbUserDefinedFunctionType.ps1' 18
#Region './Private/storedprocedures/Assert-CosmosDbStoredProcedureIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Stored Procedure Id is valid.
#>
function Assert-CosmosDbStoredProcedureIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.StoredProcedureIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/storedprocedures/Assert-CosmosDbStoredProcedureIdValid.ps1' 33
#Region './Private/storedprocedures/Set-CosmosDbStoredProcedureType.ps1' 0
function Set-CosmosDbStoredProcedureType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $StoredProcedure
    )

    foreach ($item in $StoredProcedure)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.StoredProcedure')
    }

    return $StoredProcedure
}
#EndRegion './Private/storedprocedures/Set-CosmosDbStoredProcedureType.ps1' 18
#Region './Private/databases/Assert-CosmosDbDatabaseIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Database Id is valid.
#>
function Assert-CosmosDbDatabaseIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?=]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.DatabaseIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/databases/Assert-CosmosDbDatabaseIdValid.ps1' 33
#Region './Private/databases/Set-CosmosDbDatabaseType.ps1' 0
function Set-CosmosDbDatabaseType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Database
    )

    foreach ($item in $Database)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Database')
    }

    return $Database
}
#EndRegion './Private/databases/Set-CosmosDbDatabaseType.ps1' 18
#Region './Private/utils/Convert-CosmosDbRequestBody.ps1' 0
function Convert-CosmosDbRequestBody
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Object]
        $RequestBodyObject
    )

    <#
        On PowerShell Core 6.0.x, ConvertTo-Json does not correctly escape this
        string. See https://github.com/PowerShell/PowerShell/issues/7693.

        This means that on PowerShell Core, certain strings when passed as
        Stored Procedure or Function bodies will not be accepted.

        This means that this issue https://github.com/PlagueHO/CosmosDB/issues/137
        needs to remain open.
    #>
    return ConvertTo-Json -InputObject $RequestBodyObject -Depth 100 -Compress
}
#EndRegion './Private/utils/Convert-CosmosDbRequestBody.ps1' 26
#Region './Private/utils/Convert-CosmosDbSecureStringToString.ps1' 0
<#
    .SYNOPSIS
        Decrypt a Secure String back to a string.

    .PARAMETER SecureString
        The Secure String to decrypt.

    .NOTES
        Because ConvertFrom-SecureString does not decrypt a secure string to plain
        text in PS 5.1 or PS Core 6, then we will use the BSTR method to convert it
        for those versions.

        The BSTR method does not work on PS 7 on Linux.
        Issue raised: https://github.com/PowerShell/PowerShell/issues/12125
#>
function Convert-CosmosDbSecureStringToString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.SecureString]
        $SecureString
    )

    if ($PSVersionTable.PSVersion.Major -ge 7)
    {
        $decryptedString = ConvertFrom-SecureString -SecureString $SecureString -AsPlainText
    }
    else
    {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $decryptedString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }

    return $decryptedString
}
#EndRegion './Private/utils/Convert-CosmosDbSecureStringToString.ps1' 39
#Region './Private/utils/ConvertTo-CosmosDbTokenDateString.ps1' 0
function ConvertTo-CosmosDbTokenDateString
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.DateTime]
        $Date
    )

    return $Date.ToUniversalTime().ToString("r", [System.Globalization.CultureInfo]::InvariantCulture)
}
#EndRegion './Private/utils/ConvertTo-CosmosDbTokenDateString.ps1' 15
#Region './Private/utils/Get-CosmosDbAuthorizationHeadersFromContext.ps1' 0
function Get-CosmosDbAuthorizationHeadersFromContext
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.Context]
        $Context,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ResourceLink
    )

    $headers = $null

    if ($null -ne $Context.Token)
    {
        Write-Verbose -Message $($LocalizedData.FindResourceTokenInContext -f $ResourceLink)

        # Find the most recent token non-expired matching the resource link
        $matchToken = $context.Token |
            Where-Object -FilterScript { $_.Resource -eq $ResourceLink }

        if ($matchToken)
        {
            # One or more matching tokens could be found
            Write-Verbose -Message $($LocalizedData.FoundResourceTokenInContext -f $matchToken.Count, $matchToken.Resource)

            $now = Get-Date
            $validToken = $matchToken |
                Where-Object -FilterScript { $_.Expires -gt $now } |
                Sort-Object -Property Expires -Descending |
                Select-Object -First 1

            if ($validToken)
            {
                # One or more matching tokens could be found
                Write-Verbose -Message $($LocalizedData.FoundUnExpiredResourceTokenInContext -f $validToken.Resource, $validToken.TimeStamp)

                $decryptedToken = Convert-CosmosDbSecureStringToString -SecureString $validToken.Token
                $token = [System.Web.HttpUtility]::UrlEncode($decryptedToken)
                $date = $validToken.TimeStamp
                $dateString = ConvertTo-CosmosDbTokenDateString -Date $date
                $headers = @{
                    'authorization' = $token
                    'x-ms-date'     = $dateString
                }
            }
            else
            {
                # No un-expired matching token could be found, so fall back to using a master key if possible
                Write-Verbose -Message $($LocalizedData.NoMatchingUnexpiredResourceTokenInContext -f $resourceLink)
            }
        }
        else
        {
            # No matching token could be found, so fall back to using a master key if possible
            Write-Verbose -Message $($LocalizedData.NotFoundResourceTokenInContext -f $resourceLink)
        }
    }
    else
    {
        # No tokens in context
        Write-Verbose -Message $($LocalizedData.NoResourceTokensInContext)
    }

    return $headers
}
#EndRegion './Private/utils/Get-CosmosDbAuthorizationHeadersFromContext.ps1' 72
#Region './Private/utils/Get-CosmosDbBackoffDelay.ps1' 0
function Get-CosmosDbBackoffDelay
{

    [CmdletBinding()]
    [OutputType([System.Int32])]
    param
    (
        [Parameter()]
        [CosmosDB.BackoffPolicy]
        $BackoffPolicy,

        [Parameter()]
        [System.Int32]
        $Retry = 0,

        [Parameter()]
        [System.Int32]
        $RequestedDelay = 0
    )

    if ($null -ne $BackoffPolicy)
    {
        # A back-off policy has been provided
        Write-Verbose -Message $($LocalizedData.CollectionProvisionedThroughputExceededWithBackoffPolicy)

        if ($Retry -le $BackoffPolicy.MaxRetries)
        {
            switch ($BackoffPolicy.Method)
            {
                'Default'
                {
                    $backoffPolicyDelay = $backoffPolicy.Delay
                }

                'Additive'
                {
                    $backoffPolicyDelay = $RequestedDelay + $backoffPolicy.Delay
                }

                'Linear'
                {
                    $backoffPolicyDelay = $backoffPolicy.Delay * ($Retry + 1)
                }

                'Exponential'
                {
                    $backoffPolicyDelay = $backoffPolicy.Delay * [Math]::pow(($Retry + 1),2)
                }

                'Random'
                {
                    $backoffDelayMin = -($backoffPolicy.Delay/2)
                    $backoffDelayMax = $backoffPolicy.Delay/2
                    $backoffPolicyDelay = $backoffPolicy.Delay + (Get-Random -Minimum $backoffDelayMin -Maximum $backoffDelayMax)
                }
            }

            if ($backoffPolicyDelay -gt $RequestedDelay)
            {
                $delay = $backoffPolicyDelay
                Write-Verbose -Message $($LocalizedData.BackOffPolicyAppliedPolicyDelay -f $BackoffPolicy.Method, $backoffPolicyDelay, $requestedDelay)
            }
            else
            {
                $delay = $requestedDelay
                Write-Verbose -Message $($LocalizedData.BackOffPolicyAppliedRequestedDelay -f $BackoffPolicy.Method, $backoffPolicyDelay, $requestedDelay)
            }

            return $delay
        }
        else
        {
            Write-Verbose -Message $($LocalizedData.CollectionProvisionedThroughputExceededMaxRetriesHit -f $BackoffPolicy.MaxRetries)
            return $null
        }
    }
    else
    {
        # A back-off policy has not been defined
        Write-Verbose -Message $($LocalizedData.CollectionProvisionedThroughputExceededNoBackoffPolicy)
        return $null
    }
}
#EndRegion './Private/utils/Get-CosmosDbBackoffDelay.ps1' 84
#Region './Private/utils/Get-CosmosDbUri.ps1' 0
function Get-CosmosDbUri
{

    [CmdletBinding(
        DefaultParameterSetName = 'Environment'
    )]
    [OutputType([System.Uri])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Account,

        [Parameter(ParameterSetName = 'Uri')]
        [System.String]
        $BaseHostname = 'documents.azure.com',

        [Parameter(ParameterSetName = 'Environment')]
        [CosmosDB.Environment]
        $Environment = [CosmosDB.Environment]::AzureCloud
    )

    if ($PSCmdlet.ParameterSetName -eq 'Environment')
    {
        switch ($Environment)
        {
            'AzureUSGovernment'
            {
                $BaseHostname = 'documents.azure.us'
            }

            'AzureChinaCloud'
            {
                $BaseHostname = 'documents.azure.cn'
            }
        }
    }

    return [System.Uri]::new(('https://{0}.{1}' -f $Account, $BaseHostname))
}
#EndRegion './Private/utils/Get-CosmosDbUri.ps1' 41
#Region './Private/utils/Invoke-CosmosDbRequest.ps1' 0
function Invoke-CosmosDbRequest
{
    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([System.String])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Account,

        [Parameter()]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateSet('Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace')]
        [System.String]
        $Method = 'Get',

        [Parameter(Mandatory = $True)]
        [ValidateSet('attachments', 'colls', 'dbs', 'docs', 'users', 'permissions', 'triggers', 'sprocs', 'udfs', 'offers')]
        [System.String]
        $ResourceType,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ResourcePath,

        [Parameter()]
        [System.String]
        $Body = '',

        [Parameter()]
        [ValidateSet('2014-08-21', '2015-04-08', '2015-06-03', '2015-08-06', '2015-12-16', '2016-07-11', '2017-01-19', '2017-02-22', '2017-05-03', '2017-11-15', '2018-06-18', '2018-08-31', '2018-08-31', '2018-09-17', '2018-12-31')]
        [System.String]
        $ApiVersion = '2018-09-17',

        [Parameter()]
        [Hashtable]
        $Headers = @{ },

        [Parameter()]
        [System.String]
        $ContentType = 'application/json',

        [Parameter()]
        [ValidateSet('Default', 'UTF-8')]
        [System.String]
        $Encoding = 'Default'
    )

    if ($PSCmdlet.ParameterSetName -eq 'Account')
    {
        $Context = New-CosmosDbContext -Account $Account -Database $Database -Key $Key -KeyType $KeyType
    }

    if (-not ($PSBoundParameters.ContainsKey('Database')))
    {
        $Database = $Context.Database
    }

    # Generate the resource link value that will be used in the URI and to generate the resource id
    switch ($resourceType)
    {
        'dbs'
        {
            # Request for a database object (not containined in a database)
            if ([System.String]::IsNullOrEmpty($ResourcePath))
            {
                $ResourceLink = 'dbs'
            }
            else
            {
                $resourceLink = $ResourcePath
                $resourceId = $resourceLink
            }
        }

        'offers'
        {
            # Request for an offer object (not contained in a database)
            if ([System.String]::IsNullOrEmpty($ResourcePath))
            {
                $ResourceLink = 'offers'
            }
            else
            {
                $resourceLink = $ResourcePath
                $resourceId = ($ResourceLink -split '/')[1].ToLowerInvariant()
            }
        }

        default
        {
            # Request for an object that is within a database
            $resourceLink = ('dbs/{0}' -f $Database)

            if ($PSBoundParameters.ContainsKey('ResourcePath'))
            {
                $resourceLink = ('{0}/{1}' -f $resourceLink, $ResourcePath)
            }
            else
            {
                $resourceLink = ('{0}/{1}' -f $resourceLink, $ResourceType)
            }

            # Generate the resource Id from the resource link value
            $resourceElements = [System.Collections.ArrayList] ($resourceLink -split '/')

            if (($resourceElements.Count % 2) -eq 0)
            {
                $resourceId = $resourceLink
            }
            else
            {
                $resourceElements.RemoveAt($resourceElements.Count - 1)
                $resourceId = $resourceElements -Join '/'
            }
        }
    }

    # Generate the URI from the base connection URI and the resource link
    $baseUri = $Context.BaseUri.ToString()
    $uri = [uri]::New(('{0}{1}' -f $baseUri, $resourceLink))

    # Try to build the authorization headers from the Context
    $authorizationHeaders = Get-CosmosDbAuthorizationHeadersFromContext `
        -Context $Context `
        -ResourceLink $resourceLink

    if ($null -eq $authorizationHeaders)
    {
        <#
            A token in the context that matched the resource link could not
            be found. So use the master key to generate the authorization headers
            from the token.
        #>
        if (-not ($PSBoundParameters.ContainsKey('Key')))
        {
            if (-not [System.String]::IsNullOrEmpty($Context.Key))
            {
                $Key = $Context.Key
            }
        }

        if ([System.String]::IsNullOrEmpty($Key))
        {
            New-CosmosDbInvalidOperationException -Message ($LocalizedData.ErrorAuthorizationKeyEmpty)
        }

        # Generate the date used for the authorization token
        $date = Get-Date

        $authorizationHeaders = @{
            'authorization' = New-CosmosDbAuthorizationToken `
                -Key $Key `
                -KeyType $KeyType `
                -Method $Method `
                -ResourceType $ResourceType `
                -ResourceId $resourceId `
                -Date $date
            'x-ms-date'     = ConvertTo-CosmosDbTokenDateString -Date $date
        }
    }

    $Headers += $authorizationHeaders
    $Headers.Add('x-ms-version', $ApiVersion)

    $invokeWebRequestParameters = @{
        Uri             = $uri
        Headers         = $Headers
        Method          = $method
        ContentType     = $ContentType
        UseBasicParsing = $true
    }

    if ($Method -in ('Put', 'Post', 'Patch'))
    {
        if ($Method -eq 'Patch')
        {
            $invokeWebRequestParameters['ContentType'] = 'application/json-patch+json'
        }

        if ($Encoding -eq 'UTF-8')
        {
            <#
                An encoding type of UTF-8 was passed so explictly set this in the
                request and convert to the body string to UTF8 bytes.
            #>
            $invokeWebRequestParameters['ContentType'] = ('{0}; charset={1}' -f $invokeWebRequestParameters['ContentType'], $Encoding)
            $invokeWebRequestParameters += @{
                Body = [System.Text.Encoding]::UTF8.GetBytes($Body)
            }
        }
        else
        {
            $invokeWebRequestParameters += @{
                Body = $Body
            }
        }
    }

    $requestComplete = $false
    $retry = 0

    <#
        This should initially be set to $false and changed to $true when fatal error
        is caught
    #>
    $fatal = $false

    do
    {
        try
        {
            $requestResult = Invoke-WebRequest @invokeWebRequestParameters
            $requestComplete = $true
        }
        catch [System.Net.WebException], [Microsoft.PowerShell.Commands.HttpResponseException]
        {
            if ($_.Exception.Response.StatusCode -eq 429)
            {
                <#
                    The exception was caused by exceeding provisioned throughput
                    so determine is we should delay and try again or exit
                #>
                [System.Int32] $retryAfter = ($_.Exception.Response.Headers | Where-Object -Property Key -eq 'x-ms-retry-after-ms').Value[0]

                $delay = Get-CosmosDbBackoffDelay `
                    -BackOffPolicy $Context.BackoffPolicy `
                    -Retry $retry `
                    -RequestedDelay $retryAfter

                # A null delay means retries have been exceeded or no back-off policy specified
                if ($null -ne $delay)
                {
                    $retry++
                    Write-Verbose -Message $($LocalizedData.WaitingBackoffPolicyDelay -f $retry, $delay)
                    Start-Sleep -Milliseconds $delay
                    continue
                }
            }

            if ($_.Exception.Response)
            {
                <#
                    Write out additional exception information into the verbose stream
                    In a future version a custom exception type for CosmosDB that
                    contains this additional information.
                #>

                if ($PSEdition -eq 'Core')
                {
                    # https://get-powershellblog.blogspot.com/2017/11/powershell-core-web-cmdlets-in-depth.html#L13
                    $exceptionResponse = $_.ErrorDetails
                }
                else
                {
                    $exceptionStream = $_.Exception.Response.GetResponseStream()
                    $streamReader = New-Object -TypeName System.IO.StreamReader -ArgumentList $exceptionStream
                    $exceptionResponse = $streamReader.ReadToEnd()
                }

                if ($exceptionResponse)
                {
                    Write-Verbose -Message $exceptionResponse
                }
            }

            # A non-recoverable exception occurred
            $fatal = $true

            Throw $_
        }
        catch
        {
            # A non-recoverable exception occurred
            $fatal = $true

            Throw $_
        }
    } while ($requestComplete -eq $false -and -not $fatal)

    # Display the Request Charge as a verbose message
    $requestCharge = [Uri]::UnescapeDataString($requestResult.Headers.'x-ms-request-charge').Trim()

    if ($requestCharge)
    {
        Write-Verbose -Message $($LocalizedData.RequestChargeResults -f $method, $uri, $requestCharge)
    }

    return $requestResult
}
#EndRegion './Private/utils/Invoke-CosmosDbRequest.ps1' 312
#Region './Private/utils/New-CosmosDbAuthorizationToken.ps1' 0
function New-CosmosDbAuthorizationToken
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateSet('', 'Delete', 'Get', 'Head', 'Merge', 'Options', 'Patch', 'Post', 'Put', 'Trace')]
        [System.String]
        $Method = '',

        [Parameter()]
        [System.String]
        $ResourceType = '',

        [Parameter()]
        [System.String]
        $ResourceId = '',

        [Parameter(Mandatory = $true)]
        [System.DateTime]
        $Date,

        [Parameter()]
        [ValidateSet('1.0')]
        [System.String]
        $TokenVersion = '1.0'
    )

    Write-Verbose -Message $($LocalizedData.CreateAuthorizationToken -f $Method, $ResourceType, $ResourceId, $Date)

    $decryptedKey = Convert-CosmosDbSecureStringToString -SecureString $Key
    $base64Key = [System.Convert]::FromBase64String($decryptedKey)
    $hmacSha256 = New-Object -TypeName System.Security.Cryptography.HMACSHA256 -ArgumentList (, $base64Key)
    $dateString = ConvertTo-CosmosDbTokenDateString -Date $Date
    $payLoad = @(
        $Method.ToLowerInvariant() + "`n" + `
            $ResourceType.ToLowerInvariant() + "`n" + `
            $ResourceId + "`n" + `
            $dateString.ToLowerInvariant() + "`n" + `
            "" + "`n"
    )

    $body = [System.Text.Encoding]::UTF8.GetBytes($payLoad)
    $hashPayLoad = $hmacSha256.ComputeHash($body)
    $signature = [Convert]::ToBase64String($hashPayLoad)

    Add-Type -AssemblyName 'System.Web'
    $token = [System.Web.HttpUtility]::UrlEncode(('type={0}&ver={1}&sig={2}' -f $KeyType, $TokenVersion, $signature))
    return $token
}
#EndRegion './Private/utils/New-CosmosDbAuthorizationToken.ps1' 63
#Region './Private/utils/New-CosmosDbInvalidArgumentException.ps1' 0
function New-CosmosDbInvalidArgumentException
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName
    )

    $argumentException = New-Object -TypeName 'ArgumentException' -ArgumentList @( $Message,
        $ArgumentName )
    $newObjectParams = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @( $argumentException, $ArgumentName, 'InvalidArgument', $null )
    }
    $errorRecord = New-Object @newObjectParams

    throw $errorRecord
}
#EndRegion './Private/utils/New-CosmosDbInvalidArgumentException.ps1' 28
#Region './Private/utils/New-CosmosDbInvalidOperationException.ps1' 0
function New-CosmosDbInvalidOperationException
{

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $Message)
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException'
    }
    elseif ($null -eq $ErrorRecord)
    {
        $invalidOperationException =
        New-Object -TypeName 'InvalidOperationException' -ArgumentList @( $Message )
    }
    else
    {
        $invalidOperationException =
        New-Object -TypeName 'InvalidOperationException' -ArgumentList @( $Message,
            $ErrorRecord.Exception )
    }

    $newObjectParams = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @( $invalidOperationException.ToString(), 'MachineStateIncorrect',
            'InvalidOperation', $null )
    }
    $errorRecordToThrow = New-Object @newObjectParams
    throw $errorRecordToThrow
}
#EndRegion './Private/utils/New-CosmosDbInvalidOperationException.ps1' 42
#Region './Private/utils/Repair-CosmosDbDocumentEncoding.ps1' 0
<#
    .SYNOPSIS
        Repair ISO-8859-1 encoded string to UTF-8 to fix bug
        in Invoke-WebRequest and Invoke-RestMethod in Windows
        PowerShell.

    .DESCRIPTION
        This function is used to correct the encoding of UTF-8
        results that are returned by Invoke-WebRequest and
        Invoke-RestMethod in Windows PowerShell.

        An ancient bug in Invoke-WebRequest and Invoke-RestMethod
        causes UTF-8 encoded strings to be returned as ISO-8859-1.

        This issue does not exist in PowerShell Core, so the
        string is just returned as-is.

    .PARAMETER Content
        The string to convert encodings for

    .LINK
        https://windowsserver.uservoice.com/forums/301869-powershell/suggestions/13685217-invoke-restmethod-and-invoke-webrequest-encoding-b
#>
function Repair-CosmosDbDocumentEncoding
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.String]
        $Content
    )

    if ($PSEdition -ne 'Core')
    {
        $encodingUtf8 = [System.Text.Encoding]::GetEncoding([System.Text.Encoding]::UTF8.CodePage)
        $codePageIso88591 = ([System.Text.Encoding]::GetEncodings() | Where-Object -Property Name -eq 'iso-8859-1').CodePage
        $encodingIso88591 = [System.Text.Encoding]::GetEncoding($codePageIso88591)
        $bytesUtf8 = $encodingUtf8.GetBytes($Content)
        $bytesIso88591 = [System.Text.Encoding]::Convert($encodingUtf8,$encodingIso88591,$bytesUtf8)

        return $encodingUtf8.GetString($bytesIso88591)
    }
    else
    {
        return $Content
    }
}
#EndRegion './Private/utils/Repair-CosmosDbDocumentEncoding.ps1' 51
#Region './Private/permissions/Assert-CosmosDbPermissionIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Permission Id is valid.
#>
function Assert-CosmosDbPermissionIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.PermissionIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/permissions/Assert-CosmosDbPermissionIdValid.ps1' 33
#Region './Private/permissions/Set-CosmosDbPermissionType.ps1' 0
function Set-CosmosDbPermissionType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Permission
    )

    foreach ($item in $Permission)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Permission')
    }

    return $Permission
}
#EndRegion './Private/permissions/Set-CosmosDbPermissionType.ps1' 18
#Region './Private/triggers/Assert-CosmosDbTriggerIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Trigger Id is valid.
#>
function Assert-CosmosDbTriggerIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.TriggerIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/triggers/Assert-CosmosDbTriggerIdValid.ps1' 33
#Region './Private/triggers/Set-CosmosDbTriggerType.ps1' 0
function Set-CosmosDbTriggerType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Trigger
    )

    foreach ($item in $Trigger)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Trigger')
    }

    return $Trigger
}
#EndRegion './Private/triggers/Set-CosmosDbTriggerType.ps1' 18
#Region './Private/documents/Assert-CosmosDbDocumentIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Document Id is valid.
#>
function Assert-CosmosDbDocumentIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.DocumentIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/documents/Assert-CosmosDbDocumentIdValid.ps1' 33
#Region './Private/documents/Format-CosmosDbDocumentPartitionKey.ps1' 0
<#
    .SYNOPSIS
    Helper function that assembles the partition key from an array
    for use in the 'x-ms-documentdb-partitionkey' header.
#>
function Format-CosmosDbDocumentPartitionKey
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $PartitionKey
    )

    $formattedPartitionKey = @()

    foreach ($key in $PartitionKey)
    {
        if ($key -is [System.String])
        {
            $formattedPartitionKey += "`"$key`""
        }
        elseif ($key -is [System.Int16] -or $key -is [System.Int32] -or $key -is [System.Int64])
        {
            $formattedPartitionKey += $key
        }
        else
        {
            New-CosmosDbInvalidArgumentException `
                -Message ($LocalizedData.ErrorPartitionKeyUnsupportedType -f $key, $key.GetType().FullName) `
                -ArgumentName 'PartitionKey'
        }
    }

    return '[' + ($formattedPartitionKey -join ',') + ']'
}
#EndRegion './Private/documents/Format-CosmosDbDocumentPartitionKey.ps1' 41
#Region './Private/documents/Set-CosmosDbDocumentType.ps1' 0
function Set-CosmosDbDocumentType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Document
    )

    foreach ($item in $Document)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Document')
    }

    return $Document
}
#EndRegion './Private/documents/Set-CosmosDbDocumentType.ps1' 18
#Region './Private/users/Assert-CosmosDbUserIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB User Id is valid.
#>
function Assert-CosmosDbUserIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.UserIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/users/Assert-CosmosDbUserIdValid.ps1' 33
#Region './Private/users/Set-CosmosDbUserType.ps1' 0
function Set-CosmosDbUserType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    foreach ($item in $User)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.User')
    }

    return $User
}
#EndRegion './Private/users/Set-CosmosDbUserType.ps1' 18
#Region './Private/attachments/Assert-CosmosDbAttachmentIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Attachment Id is valid.
#>
function Assert-CosmosDbAttachmentIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")

    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.AttachmentIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/attachments/Assert-CosmosDbAttachmentIdValid.ps1' 34
#Region './Private/attachments/Set-CosmosDbAttachmentType.ps1' 0
function Set-CosmosDbAttachmentType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Attachment
    )

    foreach ($item in $Attachment)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Attachment')
    }

    return $Attachment
}
#EndRegion './Private/attachments/Set-CosmosDbAttachmentType.ps1' 18
#Region './Private/collections/Assert-CosmosDbCollectionIdValid.ps1' 0
<#
    .SYNOPSIS
    Helper function that asserts a Cosmos DB Collection Id is valid.
#>
function Assert-CosmosDbCollectionIdValid
{

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName = 'Id'
    )

    $matches = [regex]::Match($Id,"[^\\/#?]{1,255}(?<!\s)")
    if ($matches.value -ne $Id)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.CollectionIdInvalid -f $Id) `
            -ArgumentName $ArgumentName
    }

    return $true
}
#EndRegion './Private/collections/Assert-CosmosDbCollectionIdValid.ps1' 33
#Region './Private/collections/Set-CosmosDbCollectionType.ps1' 0
function Set-CosmosDbCollectionType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Collection
    )

    foreach ($item in $Collection)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Collection')
        $item.indexingPolicy.PSObject.TypeNames.Insert(0, 'CosmosDB.Collection.IndexingPolicy')
        foreach ($includedPath in $item.indexingPolicy.includedPaths)
        {
            $includedPath.PSObject.TypeNames.Insert(0, 'CosmosDB.Collection.IndexingPolicy.IncludedPath')
            foreach ($index in $includedPath.indexes)
            {
                $index.PSObject.TypeNames.Insert(0, 'CosmosDB.Collection.IndexingPolicy.Index')
            }
        }
        foreach ($excludedPath in $item.indexingPolicy.excludedPaths)
        {
            $excludedPath.PSObject.TypeNames.Insert(0, 'CosmosDB.Collection.IndexingPolicy.ExcludedPath')
            foreach ($index in $excludedPath.indexes)
            {
                $index.PSObject.TypeNames.Insert(0, 'CosmosDB.Collection.IndexingPolicy.Index')
            }
        }
    }

    return $Collection
}
#EndRegion './Private/collections/Set-CosmosDbCollectionType.ps1' 35
#Region './Private/offers/Set-CosmosDbOfferType.ps1' 0
function Set-CosmosDbOfferType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $Offer
    )

    foreach ($item in $Offer)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.Offer')
    }

    return $Offer
}
#EndRegion './Private/offers/Set-CosmosDbOfferType.ps1' 18
#Region './Public/accounts/Get-CosmosDbAccount.ps1' 0
function Get-CosmosDbAccount
{

    [CmdletBinding()]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName
    )

    $getAzResource_parameters = $PSBoundParameters + @{
        ResourceType = 'Microsoft.DocumentDb/databaseAccounts'
        ApiVersion   = '2015-04-08'
    }

    Write-Verbose -Message $($LocalizedData.GettingAzureCosmosDBAccount -f $Name, $ResourceGroupName)

    return Get-AzResource @getAzResource_parameters
}
#EndRegion './Public/accounts/Get-CosmosDbAccount.ps1' 28
#Region './Public/accounts/Get-CosmosDbAccountConnectionString.ps1' 0
function Get-CosmosDbAccountConnectionString
{

    [CmdletBinding()]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter()]
        [ValidateSet('PrimaryMasterKey', 'SecondaryMasterKey', 'PrimaryReadonlyMasterKey', 'SecondaryReadonlyMasterKey')]
        [System.String]
        $MasterKeyType = 'PrimaryMasterKey'
    )

    $null = $PSBoundParameters.Remove('MasterKeyType')

    $invokeAzResourceAction_parameters = $PSBoundParameters + @{
        ResourceType = 'Microsoft.DocumentDb/databaseAccounts'
        ApiVersion   = '2015-04-08'
        Action       = 'listConnectionStrings'
        Force        = $true
    }

    Write-Verbose -Message $($LocalizedData.GettingAzureCosmosDBAccountConnectionString -f $Name, $ResourceGroupName, $MasterKeyType)

    $connectionStrings = Invoke-AzResourceAction @invokeAzResourceAction_parameters

    $connectionStringMapping = @{
        'PrimaryMasterKey' = 'Primary SQL Connection String'
        'SecondaryMasterKey' = 'Secondary SQL Connection String'
        'PrimaryReadonlyMasterKey' = 'Primary Read-Only SQL Connection String'
        'SecondaryReadonlyMasterKey' = 'Secondary Read-Only SQL Connection String'
    }

    $connectionString = $connectionStrings.connectionStrings | Where-Object -Property description -Eq $connectionStringMapping[$MasterKeyType]

    return $connectionString.connectionString
}
#EndRegion './Public/accounts/Get-CosmosDbAccountConnectionString.ps1' 48
#Region './Public/accounts/Get-CosmosDbAccountMasterKey.ps1' 0
function Get-CosmosDbAccountMasterKey
{

    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]
    [OutputType([SecureString])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter(ParameterSetName = 'AzureAccount')]
        [ValidateSet('PrimaryMasterKey', 'SecondaryMasterKey', 'PrimaryReadonlyMasterKey', 'SecondaryReadonlyMasterKey')]
        [System.String]
        $MasterKeyType = 'PrimaryMasterKey'
    )

    Write-Verbose -Message $($LocalizedData.GettingAzureCosmosDBAccountMasterKey -f $Name, $ResourceGroupName, $MasterKeyType)

    $action = 'listKeys'
    if ($MasterKeyType -in ('PrimaryReadonlyMasterKey', 'SecondaryReadonlyMasterKey'))
    {
        # Use the readonlykey Action if a ReadOnly key is required
        $action = 'readonlykeys'
    }

    $invokeAzResourceAction_parameters = @{
        Name              = $Name
        ResourceGroupName = $ResourceGroupName
        ResourceType      = 'Microsoft.DocumentDb/databaseAccounts'
        ApiVersion        = '2015-04-08'
        Action            = $action
        Force             = $true
        ErrorAction       = 'Stop'
    }

    $resource = Invoke-AzResourceAction @invokeAzResourceAction_parameters

    if ($resource)
    {
        return ConvertTo-SecureString `
            -String ($resource.$MasterKeyType) `
            -AsPlainText `
            -Force
    }
}
#EndRegion './Public/accounts/Get-CosmosDbAccountMasterKey.ps1' 54
#Region './Public/accounts/New-CosmosDbAccount.ps1' 0
function New-CosmosDbAccount
{

    [CmdletBinding(
        SupportsShouldProcess = $true
    )]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Location,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $LocationRead,

        [Parameter()]
        [ValidateSet('Eventual', 'Strong', 'Session', 'BoundedStaleness')]
        [System.String]
        $DefaultConsistencyLevel = 'Session',

        [Parameter()]
        [ValidateRange(1, 100)]
        [System.Int32]
        $MaxIntervalInSeconds = 5,

        [Parameter()]
        [ValidateRange(1, [Int32]::MaxValue)]
        [System.Int32]
        $MaxStalenessPrefix = 100,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $IpRangeFilter = @(),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $AllowedOrigin,

        [Parameter()]
        [Switch]
        $AsJob
    )

    <#
        Assemble a location object that will be used to generate the request JSON.
        It will consist of a single write location and 0 or more read locations.
    #>
    $locationObject = @(
        @{
            locationName     = $Location
            failoverPriority = 0
        })

    $failoverPriority = 1

    foreach ($locationReadItem in $LocationRead)
    {
        $locationObject += @{
            locationName     = $locationReadItem
            failoverPriority = $failoverPriority
        }
        $failoverPriority++
    }

    $consistencyPolicyObject = @{
        defaultConsistencyLevel = $DefaultConsistencyLevel
        maxIntervalInSeconds    = $MaxIntervalInSeconds
        maxStalenessPrefix      = $MaxStalenessPrefix
    }

    $cosmosDBProperties = @{
        databaseAccountOfferType = 'Standard'
        locations                = $locationObject
        consistencyPolicy        = $consistencyPolicyObject
        ipRangeFilter            = ($IpRangeFilter -join ',')
    }

    if ($PSBoundParameters.ContainsKey('AllowedOrigin'))
    {
        $corsObject = @(
            @{
                allowedOrigins = ($AllowedOrigin -join ',')
            }
        )

        $cosmosDBProperties += @{
            cors = $corsObject
        }
    }

    $null = $PSBoundParameters.Remove('LocationRead')
    $null = $PSBoundParameters.Remove('DefaultConsistencyLevel')
    $null = $PSBoundParameters.Remove('MaxIntervalInSeconds')
    $null = $PSBoundParameters.Remove('MaxStalenessPrefix')
    $null = $PSBoundParameters.Remove('IpRangeFilter')
    $null = $PSBoundParameters.Remove('AllowedOrigin')

    $newAzResource_parameters = $PSBoundParameters + @{
        ResourceType = 'Microsoft.DocumentDb/databaseAccounts'
        ApiVersion   = '2015-04-08'
        Properties   = $cosmosDBProperties
    }

    if ($PSCmdlet.ShouldProcess('Azure', ($LocalizedData.ShouldCreateAzureCosmosDBAccount -f $Name, $ResourceGroupName, $Location)))
    {
        Write-Verbose -Message $($LocalizedData.CreatingAzureCosmosDBAccount -f $Name, $ResourceGroupName, $Location)

        return (New-AzResource @newAzResource_parameters -Force)
    }
}
#EndRegion './Public/accounts/New-CosmosDbAccount.ps1' 127
#Region './Public/accounts/New-CosmosDbAccountMasterKey.ps1' 0
function New-CosmosDbAccountMasterKey
{

    [CmdletBinding(
        SupportsShouldProcess = $true
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]
    [OutputType([SecureString])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter(ParameterSetName = 'AzureAccount')]
        [ValidateSet('PrimaryMasterKey', 'SecondaryMasterKey', 'PrimaryReadonlyMasterKey', 'SecondaryReadonlyMasterKey')]
        [System.String]
        $MasterKeyType = 'PrimaryMasterKey'
    )

    Write-Verbose -Message $($LocalizedData.RegeneratingAzureCosmosDBAccountMasterKey -f $Name, $ResourceGroupName, $MasterKeyType)

    $invokeAzResourceAction_parameters = @{
        Name              = $Name
        ResourceGroupName = $ResourceGroupName
        ResourceType      = 'Microsoft.DocumentDb/databaseAccounts'
        ApiVersion        = '2015-04-08'
        Action            = 'regenerateKey'
        Force             = $true
        Parameters        = @{ keyKind = ($MasterKeyType -replace 'MasterKey','')}
        ErrorAction       = 'Stop'
    }

    if ($PSCmdlet.ShouldProcess('Azure', ($LocalizedData.ShouldCreateAzureCosmosDBAccountMasterKey -f $Name, $ResourceGroupName, $MasterKeyType)))
    {
        Invoke-AzResourceAction @invokeAzResourceAction_parameters
    }
}
#EndRegion './Public/accounts/New-CosmosDbAccountMasterKey.ps1' 45
#Region './Public/accounts/Remove-CosmosDbAccount.ps1' 0
function Remove-CosmosDbAccount
{

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter()]
        [Switch]
        $AsJob,

        [Parameter()]
        [Switch]
        $Force
    )

    if ($Force -or `
            $PSCmdlet.ShouldProcess('Azure', ($LocalizedData.ShouldRemoveAzureCosmosDBAccount -f $Name, $ResourceGroupName)))
    {
        Write-Verbose -Message $($LocalizedData.RemovingAzureCosmosDBAccount -f $Name, $ResourceGroupName)

        $removeAzResource_parameters = $PSBoundParameters + @{
            ResourceType = 'Microsoft.DocumentDb/databaseAccounts'
            ApiVersion   = '2015-04-08'
        }
        $removeAzResource_parameters['Force'] = $true

        $null = Remove-AzResource @removeAzResource_parameters
    }
}
#EndRegion './Public/accounts/Remove-CosmosDbAccount.ps1' 43
#Region './Public/accounts/Set-CosmosDbAccount.ps1' 0
function Set-CosmosDbAccount
{

    [CmdletBinding(
        SupportsShouldProcess = $true
    )]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Location,

        [Parameter()]
        [System.String[]]
        $LocationRead,

        [Parameter()]
        [ValidateSet('Eventual', 'Strong', 'Session', 'BoundedStaleness')]
        [System.String]
        $DefaultConsistencyLevel,

        [Parameter()]
        [ValidateRange(1, 100)]
        [System.Int32]
        $MaxIntervalInSeconds,

        [Parameter()]
        [ValidateRange(1, [Int32]::MaxValue)]
        [System.Int32]
        $MaxStalenessPrefix,

        [Parameter()]
        [System.String[]]
        $IpRangeFilter,

        [Parameter()]
        [System.String[]]
        $AllowedOrigin,

        [Parameter()]
        [Switch]
        $AsJob
    )

    # Get the existing Cosmos DB Account
    $getCosmosDbAccount_parameters = @{} + $PSBoundParameters
    $null = $getCosmosDbAccount_parameters.Remove('Location')
    $null = $getCosmosDbAccount_parameters.Remove('LocationRead')
    $null = $getCosmosDbAccount_parameters.Remove('DefaultConsistencyLevel')
    $null = $getCosmosDbAccount_parameters.Remove('MaxIntervalInSeconds')
    $null = $getCosmosDbAccount_parameters.Remove('MaxStalenessPrefix')
    $null = $getCosmosDbAccount_parameters.Remove('IpRangeFilter')
    $null = $getCosmosDbAccount_parameters.Remove('AllowedOrigin')
    $null = $getCosmosDbAccount_parameters.Remove('AsJob')
    $existingAccount = Get-CosmosDbAccount @getCosmosDbAccount_parameters

    if (-not $existingAccount)
    {
        New-CosmosDbInvalidOperationException -Message ($LocalizedData.ErrorAccountDoesNotExist -f $Name, $ResourceGroupName)
    }

    <#
        Assemble a location object that will be used to generate the request JSON.
        It will consist of a single write location and 0 or more read locations.
    #>
    if (-not ($PSBoundParameters.ContainsKey('Location')))
    {
        $Location = $existingAccount.Location
    }

    $locationObject = @(
        @{
            locationName     = $Location
            failoverPriority = 0
        })

    if ($PSBoundParameters.ContainsKey('LocationRead'))
    {
        $failoverPriority = 1

        foreach ($locationReadItem in $LocationRead)
        {
            $locationObject += @{
                locationName     = $locationReadItem
                failoverPriority = $failoverPriority
            }
            $failoverPriority++
        }
    }

    if (-not ($PSBoundParameters.ContainsKey('DefaultConsistencyLevel')))
    {
        $DefaultConsistencyLevel = $existingAccount.Properties.consistencyPolicy.defaultConsistencyLevel
    }

    if (-not ($PSBoundParameters.ContainsKey('MaxIntervalInSeconds')))
    {
        $MaxIntervalInSeconds = $existingAccount.Properties.consistencyPolicy.maxIntervalInSeconds
    }

    if (-not ($PSBoundParameters.ContainsKey('MaxStalenessPrefix')))
    {
        $MaxStalenessPrefix = $existingAccount.Properties.consistencyPolicy.maxStalenessPrefix
    }

    $consistencyPolicyObject = @{
        defaultConsistencyLevel = $DefaultConsistencyLevel
        maxIntervalInSeconds    = $MaxIntervalInSeconds
        maxStalenessPrefix      = $MaxStalenessPrefix
    }

    if ($PSBoundParameters.ContainsKey('IpRangeFilter'))
    {
        $ipRangeFilterString = ($IpRangeFilter -join ',')
    }
    else
    {
        $ipRangeFilterString = $existingAccount.Properties.ipRangeFilter
    }

    $cosmosDBProperties = @{
        databaseAccountOfferType = 'Standard'
        locations                = $locationObject
        consistencyPolicy        = $consistencyPolicyObject
        ipRangeFilter            = $ipRangeFilterString
    }

    if ($PSBoundParameters.ContainsKey('AllowedOrigin'))
    {
        $allowedOriginString = ($AllowedOrigin -join ',')
    }
    else
    {
        $allowedOriginString = $existingAccount.Properties.cors.allowedOrigins
    }

    if (-not ([System.String]::IsNullOrEmpty($allowedOriginString)))
    {
        $corsObject = @(
            @{
                allowedOrigins = $allowedOriginString
            }
        )

        $cosmosDBProperties += @{
            cors = $corsObject
        }
    }

    $null = $PSBoundParameters.Remove('Location')
    $null = $PSBoundParameters.Remove('LocationRead')
    $null = $PSBoundParameters.Remove('DefaultConsistencyLevel')
    $null = $PSBoundParameters.Remove('MaxIntervalInSeconds')
    $null = $PSBoundParameters.Remove('MaxStalenessPrefix')
    $null = $PSBoundParameters.Remove('IpRangeFilter')
    $null = $PSBoundParameters.Remove('AllowedOrigin')

    $setAzResource_parameters = $PSBoundParameters + @{
        ResourceType = 'Microsoft.DocumentDb/databaseAccounts'
        ApiVersion   = '2015-04-08'
        Properties   = $cosmosDBProperties
    }

    if ($PSCmdlet.ShouldProcess('Azure', ($LocalizedData.ShouldUpdateAzureCosmosDBAccount -f $Name, $ResourceGroupName)))
    {
        Write-Verbose -Message $($LocalizedData.UpdatingAzureCosmosDBAccount -f $Name, $ResourceGroupName)

        return (Set-AzResource @setAzResource_parameters -Force)
    }
}
#EndRegion './Public/accounts/Set-CosmosDbAccount.ps1' 183
#Region './Public/userdefinedfunctions/Get-CosmosDbUserDefinedFunction.ps1' 0
function Get-CosmosDbUserDefinedFunction
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbUserDefinedFunctionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('CollectionId')

    $resourcePath = ('colls/{0}/udfs' -f $CollectionId)

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'udfs' `
            -ResourcePath ('{0}/{1}' -f $resourcePath, $Id)

        $userDefinedFunction = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'udfs' `
            -ResourcePath $resourcePath

        $body = ConvertFrom-Json -InputObject $result.Content
        $userDefinedFunction = $body.UserDefinedFunctions
    }

    if ($userDefinedFunction)
    {
        return (Set-CosmosDbUserDefinedFunctionType -UserDefinedFunction $userDefinedFunction)
    }
}
#EndRegion './Public/userdefinedfunctions/Get-CosmosDbUserDefinedFunction.ps1' 76
#Region './Public/userdefinedfunctions/Get-CosmosDbUserDefinedFunctionResourcePath.ps1' 0
function Get-CosmosDbUserDefinedFunctionResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserDefinedFunctionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/colls/{1}/udfs/{2}' -f $Database, $CollectionId, $Id)
}
#EndRegion './Public/userdefinedfunctions/Get-CosmosDbUserDefinedFunctionResourcePath.ps1' 26
#Region './Public/userdefinedfunctions/New-CosmosDbUserDefinedFunction.ps1' 0
function New-CosmosDbUserDefinedFunction
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserDefinedFunctionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserDefinedFunctionBody
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('UserDefinedFunctionBody')

    $resourcePath = ('colls/{0}/udfs' -f $CollectionId)

    $UserDefinedFunctionBody = ((($UserDefinedFunctionBody -replace '`n', '\n') -replace '`r', '\r') -replace '"', '\"')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'udfs' `
        -ResourcePath $resourcePath `
        -Body "{ `"id`": `"$id`", `"body`" : `"$UserDefinedFunctionBody`" }"

    $userDefinedFunction = ConvertFrom-Json -InputObject $result.Content

    if ($userDefinedFunction)
    {
        return (Set-CosmosDbUserDefinedFunctionType -UserDefinedFunction $userDefinedFunction)
    }
}
#EndRegion './Public/userdefinedfunctions/New-CosmosDbUserDefinedFunction.ps1' 71
#Region './Public/userdefinedfunctions/Remove-CosmosDbUserDefinedFunction.ps1' 0
function Remove-CosmosDbUserDefinedFunction
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbUserDefinedFunctionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/udfs/{1}' -f $CollectionId, $Id)

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'udfs' `
        -ResourcePath $resourcePath
}
#EndRegion './Public/userdefinedfunctions/Remove-CosmosDbUserDefinedFunction.ps1' 54
#Region './Public/userdefinedfunctions/Set-CosmosDbUserDefinedFunction.ps1' 0
function Set-CosmosDbUserDefinedFunction
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserDefinedFunctionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserDefinedFunctionBody
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('UserDefinedFunctionBody')

    $resourcePath = ('colls/{0}/udfs/{1}' -f $CollectionId, $Id)

    $UserDefinedFunctionBody = ((($UserDefinedFunctionBody -replace '`n', '\n') -replace '`r', '\r') -replace '"', '\"')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'udfs' `
        -ResourcePath $resourcePath `
        -Body "{ `"id`": `"$id`", `"body`" : `"$UserDefinedFunctionBody`" }"

    $userDefinedFunction = ConvertFrom-Json -InputObject $result.Content

    if ($userDefinedFunction)
    {
        return (Set-CosmosDbUserDefinedFunctionType -UserDefinedFunction $userDefinedFunction)
    }
}
#EndRegion './Public/userdefinedfunctions/Set-CosmosDbUserDefinedFunction.ps1' 71
#Region './Public/storedprocedures/Get-CosmosDbStoredProcedure.ps1' 0
function Get-CosmosDbStoredProcedure
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbStoredProcedureIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('CollectionId')

    $resourcePath = ('colls/{0}/sprocs' -f $CollectionId)

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'sprocs' `
            -ResourcePath ('{0}/{1}' -f $resourcePath, $Id)

        $storedProcedure = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'sprocs' `
            -ResourcePath $resourcePath

        $body = ConvertFrom-Json -InputObject $result.Content
        $storedProcedure = $body.StoredProcedures
    }

    if ($storedProcedure)
    {
        return (Set-CosmosDbStoredProcedureType -StoredProcedure $storedProcedure)
    }
}
#EndRegion './Public/storedprocedures/Get-CosmosDbStoredProcedure.ps1' 76
#Region './Public/storedprocedures/Get-CosmosDbStoredProcedureResourcePath.ps1' 0
function Get-CosmosDbStoredProcedureResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbStoredProcedureIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/colls/{1}/sprocs/{2}' -f $Database, $CollectionId, $Id)
}
#EndRegion './Public/storedprocedures/Get-CosmosDbStoredProcedureResourcePath.ps1' 26
#Region './Public/storedprocedures/Invoke-CosmosDbStoredProcedure.ps1' 0
function Invoke-CosmosDbStoredProcedure
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $PartitionKey,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbStoredProcedureIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $StoredProcedureParameter
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/sprocs/{1}' -f $CollectionId, $Id)

    $headers = @{}
    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $headers += @{
            'x-ms-documentdb-partitionkey' = '["' + ($PartitionKey -join '","') + '"]'
        }
        $null = $PSBoundParameters.Remove('PartitionKey')
    }

    if ($PSBoundParameters.ContainsKey('Debug'))
    {
        $headers += @{
            'x-ms-documentdb-script-enable-logging' = $true
        }
        $null = $PSBoundParameters.Remove('Debug')
    }

    if ($PSBoundParameters.ContainsKey('StoredProcedureParameter'))
    {
        $body = ConvertTo-Json -InputObject $StoredProcedureParameter -Depth 10 -Compress
        $null = $PSBoundParameters.Remove('StoredProcedureParameter')
    }
    else
    {
        $body = '[]'
    }

    <#
        Because the headers of this request will contain important information
        then we need to use a plain web request.
    #>
    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'sprocs' `
        -ResourcePath $resourcePath `
        -Headers $headers `
        -Body $body

    if ($result.Headers.'x-ms-documentdb-script-log-results')
    {
        $logs = [Uri]::UnescapeDataString($result.Headers.'x-ms-documentdb-script-log-results').Trim()
        Write-Verbose -Message $($LocalizedData.StoredProcedureScriptLogResults -f $Id, $logs)
    }

    if ($result.Content)
    {
        return (ConvertFrom-Json -InputObject $result.Content)
    }
}
#EndRegion './Public/storedprocedures/Invoke-CosmosDbStoredProcedure.ps1' 109
#Region './Public/storedprocedures/New-CosmosDbStoredProcedure.ps1' 0
function New-CosmosDbStoredProcedure
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbStoredProcedureIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StoredProcedureBody
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('StoredProcedureBody')

    $resourcePath = ('colls/{0}/sprocs' -f $CollectionId)

    $requestBody = Convert-CosmosDbRequestBody -RequestBodyObject @{
        id = $id
        body = $StoredProcedureBody
    }

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'sprocs' `
        -ResourcePath $resourcePath `
        -Body $requestBody

    $storedProcedure = ConvertFrom-Json -InputObject $result.Content

    if ($storedProcedure)
    {
        return (Set-CosmosDbStoredProcedureType -StoredProcedure $storedProcedure)
    }
}
#EndRegion './Public/storedprocedures/New-CosmosDbStoredProcedure.ps1' 74
#Region './Public/storedprocedures/Remove-CosmosDbStoredProcedure.ps1' 0
function Remove-CosmosDbStoredProcedure
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbStoredProcedureIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/sprocs/{1}' -f $CollectionId, $Id)

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'sprocs' `
        -ResourcePath $resourcePath
}
#EndRegion './Public/storedprocedures/Remove-CosmosDbStoredProcedure.ps1' 54
#Region './Public/storedprocedures/Set-CosmosDbStoredProcedure.ps1' 0
function Set-CosmosDbStoredProcedure
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbStoredProcedureIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StoredProcedureBody
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('StoredProcedureBody')

    $resourcePath = ('colls/{0}/sprocs/{1}' -f $CollectionId, $Id)

    $requestBody = Convert-CosmosDbRequestBody -RequestBodyObject @{
        id = $id
        body = $StoredProcedureBody
    }

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'sprocs' `
        -ResourcePath $resourcePath `
        -Body $requestBody

    $storedProcedure = ConvertFrom-Json -InputObject $result.Content

    if ($storedProcedure)
    {
        return (Set-CosmosDbStoredProcedureType -StoredProcedure $storedProcedure)
    }
}
#EndRegion './Public/storedprocedures/Set-CosmosDbStoredProcedure.ps1' 74
#Region './Public/databases/Get-CosmosDbDatabase.ps1' 0
function Get-CosmosDbDatabase
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [Alias('Connection')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [Alias('Name')]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ })]
        [System.String]
        $Id
    )

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'dbs' `
            -ResourcePath ('dbs/{0}' -f $Id)

        $database = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'dbs'

        $body = ConvertFrom-Json -InputObject $result.Content

        $database = $body.Databases
    }

    if ($database)
    {
        return (Set-CosmosDbDatabaseType -Database $database)
    }
}
#EndRegion './Public/databases/Get-CosmosDbDatabase.ps1' 63
#Region './Public/databases/Get-CosmosDbDatabaseResourcePath.ps1' 0
function Get-CosmosDbDatabaseResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [Alias('Name')]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}' -f $Id)
}
#EndRegion './Public/databases/Get-CosmosDbDatabaseResourcePath.ps1' 17
#Region './Public/databases/New-CosmosDbDatabase.ps1' 0
function New-CosmosDbDatabase
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [Alias('Connection')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [Alias('Name')]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ })]
        [System.String]
        $Id,

        [ValidateRange(400, 100000)]
        [System.Int32]
        $OfferThroughput,

        [Alias('AutopilotThroughput','AutoscaleMaxThroughput','AutopilotMaxThroughput')]
        [ValidateRange(4000, 1000000)]
        [System.Int32]
        $AutoscaleThroughput
    )

    $null = $PSBoundParameters.Remove('Id')

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('OfferThroughput') -and `
        $PSBoundParameters.ContainsKey('AutoscaleThroughput'))
    {
        New-CosmosDbInvalidOperationException -Message $($LocalizedData.ErrorNewDatabaseThroughputParameterConflict)
    }

    if ($PSBoundParameters.ContainsKey('OfferThroughput'))
    {
        $headers += @{
            'x-ms-offer-throughput' = $OfferThroughput
        }
        $null = $PSBoundParameters.Remove('OfferThroughput')
    }

    if ($PSBoundParameters.ContainsKey('AutoscaleThroughput'))
    {
        $headers += @{
            'x-ms-cosmos-offer-autopilot-settings' = ConvertTo-Json -InputObject @{
                maxThroughput = $AutoscaleThroughput
            } -Compress
        }
        $null = $PSBoundParameters.Remove('AutoscaleThroughput')
    }

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'dbs' `
        -Headers $headers `
        -Body "{ `"id`": `"$id`" }"

    $database = ConvertFrom-Json -InputObject $result.Content

    if ($database)
    {
        return (Set-CosmosDbDatabaseType -Database $database)
    }
}
#EndRegion './Public/databases/New-CosmosDbDatabase.ps1' 86
#Region './Public/databases/Remove-CosmosDbDatabase.ps1' 0
function Remove-CosmosDbDatabase
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [Alias('Connection')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Alias('Name')]
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('Id')

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'dbs' `
        -ResourcePath ('dbs/{0}' -f $Id)
}
#EndRegion './Public/databases/Remove-CosmosDbDatabase.ps1' 42
#Region './Public/utils/Get-CosmosDbContinuationToken.ps1' 0
function Get-CosmosDbContinuationToken
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $ResponseHeader
    )

    $continuationToken = Get-CosmosDbResponseHeaderAttribute `
        -ResponseHeader $ResponseHeader `
        -HeaderName 'x-ms-continuation'

    if ([System.String]::IsNullOrEmpty($continuationToken))
    {
        Write-Warning -Message $LocalizedData.ResponseHeaderContinuationTokenMissingOrEmpty
        $continuationToken = $null
    }

    return $continuationToken
}
#EndRegion './Public/utils/Get-CosmosDbContinuationToken.ps1' 26
#Region './Public/utils/Get-CosmosDbResponseHeaderAttribute.ps1' 0
function Get-CosmosDbResponseHeaderAttribute
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $ResponseHeader,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $HeaderName
    )

    return ([System.String] $ResponseHeader.$HeaderName)
}
#EndRegion './Public/utils/Get-CosmosDbResponseHeaderAttribute.ps1' 21
#Region './Public/utils/New-CosmosDbBackoffPolicy.ps1' 0
function New-CosmosDbBackoffPolicy
{

    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param
    (
        [Parameter()]
        [System.Int32]
        $MaxRetries = 10,

        [Parameter()]
        [ValidateSet('Default', 'Additive', 'Linear', 'Exponential', 'Random')]
        [System.String]
        $Method = 'Default',

        [Parameter()]
        [ValidateRange(0, 3600000)]
        [System.Int32]
        $Delay = 0
    )

    $backoffPolicy = New-Object -TypeName 'CosmosDB.BackoffPolicy' -Property @{
        MaxRetries = $MaxRetries
        Method     = $Method
        Delay      = $Delay
    }

    return $backoffPolicy
}
#EndRegion './Public/utils/New-CosmosDbBackoffPolicy.ps1' 31
#Region './Public/utils/New-CosmosDbContext.ps1' 0
function New-CosmosDbContext
{
    [CmdletBinding(
        SupportsShouldProcess = $true,
        DefaultParameterSetName = 'Account'
    )]
    [OutputType([System.Management.Automation.PSCustomObject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Token')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureAccount')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CustomAccount')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CustomAzureAccount')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CustomAccount')]
        [Parameter(ParameterSetName = 'Emulator')]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [Parameter(ParameterSetName = 'CustomAccount')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Alias("ResourceGroup")]
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureAccount')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CustomAzureAccount')]
        [ValidateScript({ Assert-CosmosDbResourceGroupNameValid -ResourceGroupName $_ })]
        [System.String]
        $ResourceGroupName,

        [Parameter(ParameterSetName = 'AzureAccount')]
        [Parameter(ParameterSetName = 'CustomAzureAccount')]
        [ValidateSet('PrimaryMasterKey', 'SecondaryMasterKey', 'PrimaryReadonlyMasterKey', 'SecondaryReadonlyMasterKey')]
        [System.String]
        $MasterKeyType = 'PrimaryMasterKey',

        [Parameter(ParameterSetName = 'Emulator')]
        [Switch]
        $Emulator,

        [Parameter(ParameterSetName = 'Emulator')]
        [System.Int16]
        $Port,

        [Parameter(ParameterSetName = 'Emulator')]
        [System.String]
        $Uri,

        [Parameter(Mandatory = $true, ParameterSetName = 'Token')]
        [Parameter(ParameterSetName = 'Emulator')]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.ContextToken[]]
        $Token,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.BackoffPolicy]
        $BackoffPolicy,

        [Parameter(ParameterSetName = 'Account')]
        [Parameter(ParameterSetName = 'Token')]
        [Parameter(ParameterSetName = 'AzureAccount')]
        [CosmosDB.Environment]
        $Environment = [CosmosDB.Environment]::AzureCloud,

        [Parameter(Mandatory = $true, ParameterSetName = 'CustomAccount')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CustomAzureAccount')]
        [System.Uri]
        $EndpointHostname
    )

    switch ($PSCmdlet.ParameterSetName)
    {
        'Emulator'
        {
            $Account = 'emulator'

            if (-not ($PSBoundParameters.ContainsKey('Key')))
            {
                # This is a publically known fixed master key (see https://docs.microsoft.com/en-us/azure/cosmos-db/local-emulator#authenticating-requests)
                $Key = ConvertTo-SecureString `
                    -String 'C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==' `
                    -AsPlainText `
                    -Force
            }

            if (-not ($PSBoundParameters.ContainsKey('Uri')))
            {
                $Uri = 'https://localhost:8081'
            }

            if ($Uri -notmatch '^https?:\/\/')
            {
                $Uri = 'https://{0}' -f $Uri
            }

            if ($Uri -notmatch ':\d*$')
            {
                if ($PSBoundParameters.ContainsKey('Port'))
                {
                    Write-Warning -Message $LocalizedData.DeprecateContextPortWarning
                }
                else
                {
                    $Port = 8081
                }

                $Uri = '{0}:{1}' -f $Uri, $Port
            }

            $BaseUri = [System.Uri]::new($Uri)
        }

        'AzureAccount'
        {
            try
            {
                $null = Get-AzContext -ErrorAction SilentlyContinue
            }
            catch
            {
                $null = Connect-AzAccount -Environment $Environment
            }

            $Key = Get-CosmosDbAccountMasterKey `
                -ResourceGroupName $ResourceGroupName `
                -Name $Account `
                -MasterKeyType $MasterKeyType

            $BaseUri = Get-CosmosDbUri -Account $Account -Environment $Environment
        }

        'CustomAzureAccount'
        {
            try
            {
                $null = Get-AzContext -ErrorAction SilentlyContinue
            }
            catch
            {
                New-CosmosDbInvalidOperationException -Message ($LocalizedData.NotLoggedInToCustomCloudException)
            }

            $Key = Get-CosmosDbAccountMasterKey `
                -ResourceGroupName $ResourceGroupName `
                -Name $Account `
                -MasterKeyType $MasterKeyType

            $BaseUri = Get-CosmosDbUri -Account $Account -BaseHostname $EndpointHostname
        }

        'Account'
        {
            $BaseUri = Get-CosmosDbUri -Account $Account -Environment $Environment
        }

        'CustomAccount'
        {
            $BaseUri = Get-CosmosDbUri -Account $Account -BaseHostname $EndpointHostname
        }

        'Token'
        {
            $BaseUri = Get-CosmosDbUri -Account $Account -Environment $Environment
        }
    }

    if ($PSCmdlet.ShouldProcess('Azure', ($LocalizedData.ShouldCreateAzureCosmosDBContext -f $Account, $Database, $BaseUri)))
    {
        $context = New-Object -TypeName 'CosmosDB.Context' -Property @{
            Account       = $Account
            Database      = $Database
            Key           = $Key
            KeyType       = $KeyType
            BaseUri       = $BaseUri
            Token         = $Token
            BackoffPolicy = $BackoffPolicy
            Environment   = $Environment
        }

        return $context
    }
}
#EndRegion './Public/utils/New-CosmosDbContext.ps1' 198
#Region './Public/utils/New-CosmosDbContextToken.ps1' 0
function New-CosmosDbContextToken
{

    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope = 'Function')]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Resource,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.DateTime]
        $TimeStamp,

        [Parameter()]
        [ValidateRange(600, 18000)]
        [System.Int32]
        $TokenExpiry = 3600,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Token
    )

    $contextToken = New-Object -TypeName 'CosmosDB.ContextToken' -Property @{
        Resource  = $Resource
        TimeStamp = $TimeStamp
        Expires   = $TimeStamp.AddSeconds($TokenExpiry)
        Token     = $Token
    }

    return $contextToken
}
#EndRegion './Public/utils/New-CosmosDbContextToken.ps1' 39
#Region './Public/permissions/Get-CosmosDbPermission.ps1' 0
function Get-CosmosDbPermission
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ -ArgumentName 'UserId' })]
        [System.String]
        $UserId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbPermissionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateRange(600,18000)]
        [System.Int32]
        $TokenExpiry
    )

    $null = $PSBoundParameters.Remove('UserId')

    $resourcePath = ('users/{0}/permissions' -f $UserId)

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('TokenExpiry'))
    {
        $null = $PSBoundParameters.Remove('TokenExpiry')

        $headers += @{
            'x-ms-documentdb-expiry-seconds' = $TokenExpiry
        }
    }

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'permissions' `
            -ResourcePath ('{0}/{1}' -f $resourcePath, $Id) `
            -Headers $headers

        $permission = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'permissions' `
            -ResourcePath $resourcePath `
            -Headers $headers

        $body = ConvertFrom-Json -InputObject $result.Content

        $permission = $body.Permissions
    }

    if ($permission)
    {
        return (Set-CosmosDbPermissionType -Permission $permission)
    }
}
#EndRegion './Public/permissions/Get-CosmosDbPermission.ps1' 95
#Region './Public/permissions/Get-CosmosDbPermissionResourcePath.ps1' 0
function Get-CosmosDbPermissionResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ -ArgumentName 'UserId' })]
        [System.String]
        $UserId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbPermissionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/users/{1}/permissions/{2}' -f $Database, $UserId, $Id)
}
#EndRegion './Public/permissions/Get-CosmosDbPermissionResourcePath.ps1' 26
#Region './Public/permissions/New-CosmosDbPermission.ps1' 0
function New-CosmosDbPermission
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ -ArgumentName 'UserId' })]
        [System.String]
        $UserId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbPermissionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Resource,

        [Parameter()]
        [ValidateSet('All', 'Read')]
        [System.String]
        $PermissionMode = 'All'
    )

    $null = $PSBoundParameters.Remove('UserId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('Resource')
    $null = $PSBoundParameters.Remove('PermissionMode')

    $resourcePath = ('users/{0}/permissions' -f $UserId)

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'permissions' `
        -ResourcePath $resourcePath `
        -Body "{ `"id`": `"$id`", `"permissionMode`" : `"$PermissionMode`", `"resource`" : `"$Resource`" }"

    $permission = ConvertFrom-Json -InputObject $result.Content

    if ($permission)
    {
        return (Set-CosmosDbPermissionType -Permission $permission)
    }
}
#EndRegion './Public/permissions/New-CosmosDbPermission.ps1' 75
#Region './Public/permissions/Remove-CosmosDbPermission.ps1' 0
function Remove-CosmosDbPermission
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ -ArgumentName 'UserId' })]
        [System.String]
        $UserId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbPermissionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('UserId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('users/{0}/permissions/{1}' -f $UserId,$Id)

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'permissions' `
        -ResourcePath $resourcePath
}
#EndRegion './Public/permissions/Remove-CosmosDbPermission.ps1' 54
#Region './Public/triggers/Get-CosmosDbTrigger.ps1' 0
function Get-CosmosDbTrigger
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbTriggerIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('CollectionId')

    $resourcePath = ('colls/{0}/triggers' -f $CollectionId)

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'triggers' `
            -ResourcePath ('{0}/{1}' -f $resourcePath, $Id)

        $trigger = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'triggers' `
            -ResourcePath $resourcePath

        $body = ConvertFrom-Json -InputObject $result.Content
        $trigger = $body.Triggers
    }

    if ($trigger)
    {
        return (Set-CosmosDbTriggerType -Trigger $trigger)
    }
}
#EndRegion './Public/triggers/Get-CosmosDbTrigger.ps1' 76
#Region './Public/triggers/Get-CosmosDbTriggerResourcePath.ps1' 0
function Get-CosmosDbTriggerResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbTriggerIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/colls/{1}/triggers/{2}' -f $Database, $CollectionId, $Id)
}
#EndRegion './Public/triggers/Get-CosmosDbTriggerResourcePath.ps1' 26
#Region './Public/triggers/New-CosmosDbTrigger.ps1' 0
function New-CosmosDbTrigger
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbTriggerIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $TriggerBody,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Create', 'Replace', 'Delete')]
        [System.String]
        $TriggerOperation,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Pre', 'Post')]
        [System.String]
        $TriggerType
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('TriggerBody')
    $null = $PSBoundParameters.Remove('TriggerOperation')
    $null = $PSBoundParameters.Remove('TriggerType')

    $resourcePath = ('colls/{0}/triggers' -f $CollectionId)

    $TriggerBody = ((($TriggerBody -replace '`n', '\n') -replace '`r', '\r') -replace '"', '\"')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'triggers' `
        -ResourcePath $resourcePath `
        -Body "{ `"id`": `"$id`", `"body`" : `"$TriggerBody`", `"triggerOperation`" : `"$triggerOperation`", `"triggerType`" : `"$triggerType`" }"

    $trigger = ConvertFrom-Json -InputObject $result.Content

    if ($trigger)
    {
        return (Set-CosmosDbTriggerType -Trigger $trigger)
    }
}
#EndRegion './Public/triggers/New-CosmosDbTrigger.ps1' 83
#Region './Public/triggers/Remove-CosmosDbTrigger.ps1' 0
function Remove-CosmosDbTrigger
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbTriggerIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/triggers/{1}' -f $CollectionId, $Id)

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'triggers' `
        -ResourcePath $resourcePath
}
#EndRegion './Public/triggers/Remove-CosmosDbTrigger.ps1' 54
#Region './Public/triggers/Set-CosmosDbTrigger.ps1' 0
function Set-CosmosDbTrigger
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbTriggerIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $TriggerBody,

        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Create', 'Replace', 'Delete')]
        [System.String]
        $TriggerOperation,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Pre', 'Post')]
        [System.String]
        $TriggerType
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('TriggerBody')
    $null = $PSBoundParameters.Remove('TriggerOperation')
    $null = $PSBoundParameters.Remove('TriggerType')

    $resourcePath = ('colls/{0}/triggers/{1}' -f $CollectionId, $Id)

    $TriggerBody = ((($TriggerBody -replace '`n', '\n') -replace '`r', '\r') -replace '"', '\"')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'triggers' `
        -ResourcePath $resourcePath `
        -Body "{ `"id`": `"$id`", `"body`" : `"$TriggerBody`", `"triggerOperation`" : `"$triggerOperation`", `"triggerType`" : `"$triggerType`" }"

    $trigger = ConvertFrom-Json -InputObject $result.Content

    if ($trigger)
    {
        return (Set-CosmosDbTriggerType -Trigger $trigger)
    }
}
#EndRegion './Public/triggers/Set-CosmosDbTrigger.ps1' 83
#Region './Public/documents/Get-CosmosDbDocument.ps1' 0
function Get-CosmosDbDocument
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $PartitionKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Int32]
        $MaxItemCount = -1,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContinuationToken,

        [Parameter()]
        [ValidateSet('Strong', 'Bounded', 'Session', 'Eventual')]
        [System.String]
        $ConsistencyLevel,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SessionToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PartitionKeyRangeId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Query,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Hashtable[]]
        $QueryParameters,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $QueryEnableCrossPartition = $False,

        [Alias("ResultHeaders")]
        [Parameter()]
        [ref]
        $ResponseHeader,

        [Parameter()]
        [switch]
        $ReturnJson
    )

    $null = $PSBoundParameters.Remove('ReturnJson')

    $documentJson = Get-CosmosDbDocumentJson @PSBoundParameters

    if ($ReturnJson.IsPresent)
    {
        return $documentJson
    }
    else
    {
        try
        {
            $documents = ConvertFrom-Json -InputObject $documentJson

            if ([System.String]::IsNullOrEmpty($Id))
            {
                $documents = $documents.Documents
            }

            if ($documents)
            {
                return (Set-CosmosDbDocumentType -Document $documents)
            }
        }
        catch
        {
            New-CosmosDbInvalidOperationException -Message ($LocalizedData.ErrorConvertingDocumentJsonToObject)
        }
    }
}
#EndRegion './Public/documents/Get-CosmosDbDocument.ps1' 129
#Region './Public/documents/Get-CosmosDbDocumentJson.ps1' 0
function Get-CosmosDbDocumentJson
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $PartitionKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Int32]
        $MaxItemCount = -1,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContinuationToken,

        [Parameter()]
        [ValidateSet('Strong', 'Bounded', 'Session', 'Eventual')]
        [System.String]
        $ConsistencyLevel,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SessionToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PartitionKeyRangeId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Query,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Hashtable[]]
        $QueryParameters,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $QueryEnableCrossPartition = $False,

        [Alias("ResultHeaders")]
        [Parameter()]
        [ref]
        $ResponseHeader
    )

    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('MaxItemCount')
    $null = $PSBoundParameters.Remove('ContinuationToken')
    $null = $PSBoundParameters.Remove('ConsistencyLevel')
    $null = $PSBoundParameters.Remove('SessionToken')
    $null = $PSBoundParameters.Remove('PartitionKeyRangeId')
    $null = $PSBoundParameters.Remove('Query')
    $null = $PSBoundParameters.Remove('QueryParameters')
    $null = $PSBoundParameters.Remove('QueryEnableCrossPartition')

    if ($PSBoundParameters.ContainsKey('ResponseHeader'))
    {
        $ResponseHeaderPassed = $true
        $null = $PSBoundParameters.Remove('ResponseHeader')
    }

    $resourcePath = ('colls/{0}/docs' -f $CollectionId)
    $method = 'Get'
    $headers = @{}

    if ([System.String]::IsNullOrEmpty($Id))
    {
        $body = ''

        if (-not [System.String]::IsNullOrEmpty($Query))
        {
            # A query has been specified
            $method = 'Post'

            $headers += @{
                'x-ms-documentdb-isquery' = $True
            }

            if ($QueryEnableCrossPartition -eq $True)
            {
                $headers += @{
                    'x-ms-documentdb-query-enablecrosspartition' = $True
                }
            }

            # Set the content type to application/query+json for querying
            $null = $PSBoundParameters.Add('ContentType', 'application/query+json')

            # Create the body JSON for the query
            $bodyObject = @{
                query = $Query
            }

            if (-not [System.String]::IsNullOrEmpty($QueryParameters))
            {
                $bodyObject += @{ parameters = $QueryParameters }
            }

            $body = ConvertTo-Json -InputObject $bodyObject
        }
        else
        {
            if (-not [System.String]::IsNullOrEmpty($PartitionKeyRangeId))
            {
                $headers += @{
                    'x-ms-documentdb-partitionkeyrangeid' = $PartitionKeyRangeId
                }
            }
        }

        # The following headers apply when querying documents or just getting a list
        if ($PSBoundParameters.ContainsKey('PartitionKey'))
        {
            $headers += @{
                'x-ms-documentdb-partitionkey' = Format-CosmosDbDocumentPartitionKey -PartitionKey $PartitionKey
            }
            $null = $PSBoundParameters.Remove('PartitionKey')
        }

        $headers += @{
            'x-ms-max-item-count' = $MaxItemCount
        }

        if (-not [System.String]::IsNullOrEmpty($ContinuationToken))
        {
            $headers += @{
                'x-ms-continuation' = $ContinuationToken
            }
        }

        if (-not [System.String]::IsNullOrEmpty($ConsistencyLevel))
        {
            $headers += @{
                'x-ms-consistency-level' = $ConsistencyLevel
            }
        }

        if (-not [System.String]::IsNullOrEmpty($SessionToken))
        {
            $headers += @{
                'x-ms-session-token' = $SessionToken
            }
        }

        <#
            Because the headers of this request will contain important information
            then we need to use a plain web request.
        #>
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method $method `
            -ResourceType 'docs' `
            -ResourcePath $resourcePath `
            -Headers $headers `
            -Body $body

        if ($ResponseHeaderPassed)
        {
            # Return the result headers
            $ResponseHeader.value = $result.Headers
        }
    }
    else
    {
        # A document Id has been specified
        if ($PSBoundParameters.ContainsKey('PartitionKey'))
        {
            $headers += @{
                'x-ms-documentdb-partitionkey' = Format-CosmosDbDocumentPartitionKey -PartitionKey $PartitionKey
            }
            $null = $PSBoundParameters.Remove('PartitionKey')
        }

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method $method `
            -Headers $headers `
            -ResourceType 'docs' `
            -ResourcePath ('{0}/{1}' -f $resourcePath, $Id)
    }

    $documents = Repair-CosmosDbDocumentEncoding -Content $result.Content

    return $documents
}
#EndRegion './Public/documents/Get-CosmosDbDocumentJson.ps1' 234
#Region './Public/documents/Get-CosmosDbDocumentResourcePath.ps1' 0
function Get-CosmosDbDocumentResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/colls/{1}/docs/{2}' -f $Database, $CollectionId, $Id)
}
#EndRegion './Public/documents/Get-CosmosDbDocumentResourcePath.ps1' 26
#Region './Public/documents/New-CosmosDbDocument.ps1' 0
function New-CosmosDbDocument
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DocumentBody,

        [Parameter()]
        [ValidateSet('Include', 'Exclude')]
        [System.String]
        $IndexingDirective,

        [Parameter()]
        [System.Boolean]
        $Upsert,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $PartitionKey,

        [Parameter()]
        [ValidateSet('Default', 'UTF-8')]
        [System.String]
        $Encoding = 'Default',

        [Parameter()]
        [switch]
        $ReturnJson
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('DocumentBody')
    $null = $PSBoundParameters.Remove('ReturnJson')

    $resourcePath = ('colls/{0}/docs' -f $CollectionId)

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('Upsert'))
    {
        $headers += @{
            'x-ms-documentdb-is-upsert' = $Upsert
        }
        $null = $PSBoundParameters.Remove('Upsert')
    }

    if ($PSBoundParameters.ContainsKey('IndexingDirective'))
    {
        $headers += @{
            'x-ms-indexing-directive' = $IndexingDirective
        }
        $null = $PSBoundParameters.Remove('IndexingDirective')
    }

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $headers += @{
            'x-ms-documentdb-partitionkey' = Format-CosmosDbDocumentPartitionKey -PartitionKey $PartitionKey
        }
        $null = $PSBoundParameters.Remove('PartitionKey')
    }

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'docs' `
        -ResourcePath $resourcePath `
        -Body $DocumentBody `
        -Headers $headers

    if ($ReturnJson.IsPresent)
    {
        return $result.Content
    }
    else
    {
        try
        {
            $document = ConvertFrom-Json -InputObject $result.Content
        }
        catch
        {
            New-CosmosDbInvalidOperationException -Message ($LocalizedData.ErrorConvertingDocumentJsonToObject)
        }

        if ($document)
        {
            return (Set-CosmosDbDocumentType -Document $document)
        }
    }
}
#EndRegion './Public/documents/New-CosmosDbDocument.ps1' 129
#Region './Public/documents/Remove-CosmosDbDocument.ps1' 0
function Remove-CosmosDbDocument
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $PartitionKey
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/docs/{1}' -f $CollectionId, $Id)

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $headers += @{
            'x-ms-documentdb-partitionkey' = Format-CosmosDbDocumentPartitionKey -PartitionKey $PartitionKey
        }
        $null = $PSBoundParameters.Remove('PartitionKey')
    }

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'docs' `
        -ResourcePath $resourcePath `
        -Headers $headers
}
#EndRegion './Public/documents/Remove-CosmosDbDocument.ps1' 70
#Region './Public/documents/Set-CosmosDbDocument.ps1' 0
function Set-CosmosDbDocument
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DocumentBody,

        [Parameter()]
        [ValidateSet('Include', 'Exclude')]
        [System.String]
        $IndexingDirective,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $PartitionKey,

        [Alias('IfMatch')]
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ETag,

        [Parameter()]
        [ValidateSet('Default', 'UTF-8')]
        [System.String]
        $Encoding = 'Default',

        [Parameter()]
        [switch]
        $ReturnJson
    )

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('DocumentBody')
    $null = $PSBoundParameters.Remove('ReturnJson')

    $resourcePath = ('colls/{0}/docs/{1}' -f $CollectionId, $Id)

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('IndexingDirective'))
    {
        $headers += @{
            'x-ms-indexing-directive' = $IndexingDirective
        }
        $null = $PSBoundParameters.Remove('IndexingDirective')
    }

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $headers += @{
            'x-ms-documentdb-partitionkey' = Format-CosmosDbDocumentPartitionKey -PartitionKey $PartitionKey
        }
        $null = $PSBoundParameters.Remove('PartitionKey')
    }

    if ($PSBoundParameters.ContainsKey('ETag'))
    {
        $headers += @{
            'If-Match' = $Etag
        }
        $null = $PSBoundParameters.Remove('ETag')
    }

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'docs' `
        -ResourcePath $resourcePath `
        -Body $DocumentBody `
        -Headers $headers

    if ($ReturnJson.IsPresent)
    {
        return $result.Content
    }
    else
    {
        try
        {
            $document = ConvertFrom-Json -InputObject $result.Content
        }
        catch
        {
            New-CosmosDbInvalidOperationException -Message ($LocalizedData.ErrorConvertingDocumentJsonToObject)
        }

        if ($document)
        {
            return (Set-CosmosDbDocumentType -Document $document)
        }
    }
}
#EndRegion './Public/documents/Set-CosmosDbDocument.ps1' 136
#Region './Public/users/Get-CosmosDbUser.ps1' 0
function Get-CosmosDbUser
{
    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ })]
        [System.String]
        $Id
    )

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'users' `
            -ResourcePath ('users/{0}' -f $Id)

        $user = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'users'

        $body = ConvertFrom-Json -InputObject $result.Content

        $user = $body.Users
    }

    if ($user)
    {
        return (Set-CosmosDbUserType -User $user)
    }
}
#EndRegion './Public/users/Get-CosmosDbUser.ps1' 66
#Region './Public/users/Get-CosmosDbUserResourcePath.ps1' 0
function Get-CosmosDbUserResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/users/{1}' -f $Database, $Id)
}
#EndRegion './Public/users/Get-CosmosDbUserResourcePath.ps1' 21
#Region './Public/users/New-CosmosDbUser.ps1' 0
function New-CosmosDbUser
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('Id')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'users' `
        -Body "{ `"id`": `"$Id`" }"

    $user = ConvertFrom-Json -InputObject $result.Content

    if ($user)
    {
        return (Set-CosmosDbUserType -User $user)
    }
}
#EndRegion './Public/users/New-CosmosDbUser.ps1' 54
#Region './Public/users/Remove-CosmosDbUser.ps1' 0
function Remove-CosmosDbUser
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('Id')

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'users' `
        -ResourcePath ('users/{0}' -f $Id)
}
#EndRegion './Public/users/Remove-CosmosDbUser.ps1' 46
#Region './Public/users/Set-CosmosDbUser.ps1' 0
function Set-CosmosDbUser
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbUserIdValid -Id $_ -ArgumentName 'NewId' })]
        [System.String]
        $NewId
    )

    $null = $PSBoundParameters.Remove('Id')
    $null = $PSBoundParameters.Remove('NewId')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'users' `
        -ResourcePath ('users/{0}' -f $Id) `
        -Body "{ `"id`": `"$NewId`" }"

    $user = ConvertFrom-Json -InputObject $result.Content

    if ($user)
    {
        return (Set-CosmosDbUserType -User $user)
    }
}
#EndRegion './Public/users/Set-CosmosDbUser.ps1' 61
#Region './Public/users/Set-CosmosDbUserType.ps1' 0
function Set-CosmosDbUserType
{

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )

    foreach ($item in $User)
    {
        $item.PSObject.TypeNames.Insert(0, 'CosmosDB.User')
    }

    return $User
}
#EndRegion './Public/users/Set-CosmosDbUserType.ps1' 18
#Region './Public/attachments/Get-CosmosDbAttachment.ps1' 0
function Get-CosmosDbAttachment
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ -ArgumentName 'DocumentId' })]
        [System.String]
        $DocumentId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbAttachmentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $PartitionKey
    )

    Write-Warning -Message $LocalizedData.DeprecateAttachmentWarning

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('DocumentId')

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $null = $PSBoundParameters.Remove('PartitionKey')
        $headers += @{
            'x-ms-documentdb-partitionkey' = '["' + ($PartitionKey -join '","') + '"]'
        }
    }

    $resourcePath = ('colls/{0}/docs/{1}/attachments' -f $CollectionId, $DocumentId)

    if (-not [System.String]::IsNullOrEmpty($Id))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'attachments' `
            -ResourcePath ('{0}/{1}' -f $resourcePath, $Id) `
            -Headers $headers

        $attachment = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'attachments' `
            -ResourcePath $resourcePath `
            -Headers $headers

        $body = ConvertFrom-Json -InputObject $result.Content
        $attachment = $body.Attachments
    }

    if ($attachment)
    {
        return (Set-CosmosDbAttachmentType -Attachment $attachment)
    }
}
#EndRegion './Public/attachments/Get-CosmosDbAttachment.ps1' 101
#Region './Public/attachments/Get-CosmosDbAttachmentResourcePath.ps1' 0
function Get-CosmosDbAttachmentResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ -ArgumentName 'DocumentId' })]
        [System.String]
        $DocumentId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAttachmentIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/colls/{1}/docs/{2}/attachments/{3}' -f $Database, $CollectionId, $DocumentId, $Id)
}
#EndRegion './Public/attachments/Get-CosmosDbAttachmentResourcePath.ps1' 31
#Region './Public/attachments/New-CosmosDbAttachment.ps1' 0
function New-CosmosDbAttachment
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ -ArgumentName 'DocumentId' })]
        [System.String]
        $DocumentId,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbAttachmentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $PartitionKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContentType,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Media,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Slug
    )

    Write-Warning -Message $LocalizedData.DeprecateAttachmentWarning

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('DocumentId')

    $resourcePath = ('colls/{0}/docs/{1}/attachments' -f $CollectionId, $DocumentId)

    $headers = @{}
    $bodyObject = @{}

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')
        $bodyObject += @{ id = $Id }
    }

    if ($PSBoundParameters.ContainsKey('ContentType'))
    {
        $null = $PSBoundParameters.Remove('ContentType')
        $bodyObject += @{ contentType = $ContentType }
    }

    if ($PSBoundParameters.ContainsKey('Media'))
    {
        $null = $PSBoundParameters.Remove('Media')
        $bodyObject += @{ media = $Media }
    }

    if ($PSBoundParameters.ContainsKey('Slug'))
    {
        $null = $PSBoundParameters.Remove('Slug')
        $headers += @{
            'Slug' = $Slug
        }
    }

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $null = $PSBoundParameters.Remove('PartitionKey')
        $headers += @{
            'x-ms-documentdb-partitionkey' = '["' + ($PartitionKey -join '","') + '"]'
        }
    }

    $body = ConvertTo-Json -InputObject $bodyObject

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'attachments' `
        -ResourcePath $resourcePath `
        -Body $body `
        -Headers $headers

    $attachment = ConvertFrom-Json -InputObject $result.Content

    if ($attachment)
    {
        return (Set-CosmosDbAttachmentType -Attachment $attachment)
    }
}
#EndRegion './Public/attachments/New-CosmosDbAttachment.ps1' 130
#Region './Public/attachments/Remove-CosmosDbAttachment.ps1' 0
function Remove-CosmosDbAttachment
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ -ArgumentName 'DocumentId' })]
        [System.String]
        $DocumentId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAttachmentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $PartitionKey
    )

    Write-Warning -Message $LocalizedData.DeprecateAttachmentWarning

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('DocumentId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/docs/{1}/attachments/{2}' -f $CollectionId, $DocumentId, $Id)

    $headers = @{}

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $null = $PSBoundParameters.Remove('PartitionKey')
        $headers += @{
            'x-ms-documentdb-partitionkey' = '["' + ($PartitionKey -join '","') + '"]'
        }
    }

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'attachments' `
        -ResourcePath $resourcePath `
        -Header $headers
}
#EndRegion './Public/attachments/Remove-CosmosDbAttachment.ps1' 78
#Region './Public/attachments/Set-CosmosDbAttachment.ps1' 0
function Set-CosmosDbAttachment
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ -ArgumentName 'CollectionId' })]
        [System.String]
        $CollectionId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDocumentIdValid -Id $_ -ArgumentName 'DocumentId' })]
        [System.String]
        $DocumentId,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbAttachmentIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbAttachmentIdValid -Id $_ -ArgumentName 'NewId' })]
        [System.String]
        $NewId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $PartitionKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContentType,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Media,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Slug
    )

    Write-Warning -Message $LocalizedData.DeprecateAttachmentWarning

    $null = $PSBoundParameters.Remove('CollectionId')
    $null = $PSBoundParameters.Remove('DocumentId')
    $null = $PSBoundParameters.Remove('Id')

    $resourcePath = ('colls/{0}/docs/{1}/attachments/{2}' -f $CollectionId, $DocumentId, $Id)

    $headers = @{}
    $bodyObject = @{}

    if ($PSBoundParameters.ContainsKey('NewId'))
    {
        $null = $PSBoundParameters.Remove('NewId')
        $bodyObject += @{ id = $NewId }
    }
    else
    {
        $bodyObject += @{ id = $Id }
    }

    if ($PSBoundParameters.ContainsKey('ContentType'))
    {
        $null = $PSBoundParameters.Remove('ContentType')
        $bodyObject += @{ contentType = $ContentType }
    }

    if ($PSBoundParameters.ContainsKey('Media'))
    {
        $null = $PSBoundParameters.Remove('Media')
        $bodyObject += @{ media = $Media }
    }

    if ($PSBoundParameters.ContainsKey('Slug'))
    {
        $null = $PSBoundParameters.Remove('Slug')
        $headers += @{
            'Slug' = $Slug
        }
    }

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $null = $PSBoundParameters.Remove('PartitionKey')
        $headers += @{
            'x-ms-documentdb-partitionkey' = '["' + ($PartitionKey -join '","') + '"]'
        }
    }

    $body = ConvertTo-Json -InputObject $bodyObject

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'attachments' `
        -ResourcePath $resourcePath `
        -Body $body `
        -Headers $headers

    $attachment = ConvertFrom-Json -InputObject $result.Content

    if ($attachment)
    {
        return (Set-CosmosDbAttachmentType -Attachment $attachment)
    }
}
#EndRegion './Public/attachments/Set-CosmosDbAttachment.ps1' 140
#Region './Public/collections/Get-CosmosDbCollection.ps1' 0
function Get-CosmosDbCollection
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Alias('Name')]
        [Parameter()]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Int32]
        $MaxItemCount = -1,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContinuationToken,

        [Alias("ResultHeaders")]
        [Parameter()]
        [ref]
        $ResponseHeader
    )

    $null = $PSBoundParameters.Remove('MaxItemCount')
    $null = $PSBoundParameters.Remove('ContinuationToken')

    if ($PSBoundParameters.ContainsKey('ResponseHeader'))
    {
        $ResponseHeaderPassed = $true
        $null = $PSBoundParameters.Remove('ResponseHeader')
    }

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'colls' `
            -ResourcePath ('colls/{0}' -f $Id)

        $collection = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        $headers = @{
            'x-ms-max-item-count' = $MaxItemCount
        }

        if (-not [System.String]::IsNullOrEmpty($ContinuationToken))
        {
            $headers += @{
                'x-ms-continuation' = $ContinuationToken
            }
        }

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'colls' `
            -Headers $headers

        $body = ConvertFrom-Json -InputObject $result.Content
        $collection = $body.DocumentCollections
    }


    if ($ResponseHeaderPassed)
    {
        # Return the result headers
        $ResponseHeader.value = $result.Headers
    }

    if ($collection)
    {
        return (Set-CosmosDbCollectionType -Collection $collection)
    }
}
#EndRegion './Public/collections/Get-CosmosDbCollection.ps1' 110
#Region './Public/collections/Get-CosmosDbCollectionResourcePath.ps1' 0
function Get-CosmosDbCollectionResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Alias('Name')]
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    return ('dbs/{0}/colls/{1}' -f $Database, $Id)
}
#EndRegion './Public/collections/Get-CosmosDbCollectionResourcePath.ps1' 22
#Region './Public/collections/Get-CosmosDbCollectionSize.ps1' 0
function Get-CosmosDbCollectionSize
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Alias('Name')]
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    <#
        per https://docs.microsoft.com/en-us/azure/cosmos-db/monitor-accounts,
        The quota and usage information for the collection is returned in the
        x-ms-resource-quota and x-ms-resource-usage headers in the response.
    #>

    $null = $PSBoundParameters.Remove('Id')

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Get' `
        -ResourceType 'colls' `
        -ResourcePath ('colls/{0}' -f $Id)

    $usageItems = @{}
    $resources = ($result.headers["x-ms-resource-usage"]).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)

    foreach ($resource in $resources)
    {
        [System.String] $k, $v = $resource.Split('=')
        $usageItems[$k] = $v
    }

    if ($usageItems)
    {
        return $usageItems
    }
}
#EndRegion './Public/collections/Get-CosmosDbCollectionSize.ps1' 68
#Region './Public/collections/New-CosmosDbCollection.ps1' 0
function New-CosmosDbCollection
{

    [CmdletBinding(DefaultParameterSetName = 'ContextIndexPolicy')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ContextIndexPolicy')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ContextIndexPolicyJson')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'AccountIndexPolicy')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AccountIndexPolicyJson')]
        [ValidateScript( { Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript( { Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Alias('Name')]
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Assert-CosmosDbCollectionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateRange(400, 250000)]
        [System.Int32]
        $OfferThroughput,

        [Parameter()]
        [ValidateSet('S1', 'S2', 'S3')]
        [System.String]
        $OfferType,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PartitionKey,

        [Parameter(ParameterSetName = 'ContextIndexPolicy')]
        [Parameter(ParameterSetName = 'AccountIndexPolicy')]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.IndexingPolicy.Policy]
        $IndexingPolicy,

        [Parameter(ParameterSetName = 'ContextIndexPolicyJson')]
        [Parameter(ParameterSetName = 'AccountIndexPolicyJson')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $IndexingPolicyJson,

        [Parameter()]
        [ValidateRange(-1, 2147483647)]
        [System.Int32]
        $DefaultTimeToLive,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.UniqueKeyPolicy.Policy]
        $UniqueKeyPolicy,

        [Alias('AutopilotThroughput')]
        [ValidateRange(4000, 1000000)]
        [System.Int32]
        $AutoscaleThroughput
    )

    $headers = @{ }

    if (($PSBoundParameters.ContainsKey('OfferThroughput') -and $PSBoundParameters.ContainsKey('OfferType')) -or `
        ($PSBoundParameters.ContainsKey('OfferThroughput') -and $PSBoundParameters.ContainsKey('AutoscaleThroughput')) -or `
        ($PSBoundParameters.ContainsKey('OfferType') -and $PSBoundParameters.ContainsKey('AutoscaleThroughput')))
    {
        New-CosmosDbInvalidOperationException -Message $($LocalizedData.ErrorNewCollectionOfferParameterConflict)
    }

    if ($PSBoundParameters.ContainsKey('OfferThroughput'))
    {
        if ($OfferThroughput -gt 10000 -and -not ($PSBoundParameters.ContainsKey('PartitionKey')))
        {
            New-CosmosDbInvalidOperationException -Message $($LocalizedData.ErrorNewCollectionParitionKeyOfferRequired)
        }

        $headers += @{
            'x-ms-offer-throughput' = $OfferThroughput
        }
        $null = $PSBoundParameters.Remove('OfferThroughput')
    }

    if ($PSBoundParameters.ContainsKey('OfferType'))
    {
        Write-Warning -Message $LocalizedData.WarningNewCollectionOfferTypeDeprecated
        $headers += @{
            'x-ms-offer-type' = $OfferType
        }
        $null = $PSBoundParameters.Remove('OfferType')
    }

    if ($PSBoundParameters.ContainsKey('AutoscaleThroughput'))
    {
        if (-not ($PSBoundParameters.ContainsKey('PartitionKey')))
        {
            New-CosmosDbInvalidOperationException -Message $($LocalizedData.ErrorNewCollectionParitionKeyAutoscaleRequired)
        }

        $headers += @{
            'x-ms-cosmos-offer-autopilot-settings' = ConvertTo-Json -InputObject @{
                maxThroughput = $AutoscaleThroughput
            } -Compress
        }
        $null = $PSBoundParameters.Remove('AutoscaleThroughput')
    }

    $null = $PSBoundParameters.Remove('Id')

    $bodyObject = @{
        id = $id
    }

    if ($PSBoundParameters.ContainsKey('PartitionKey'))
    {
        $bodyObject += @{
            partitionKey = @{
                paths = @('/{0}' -f $PartitionKey.TrimStart('/'))
                kind  = 'Hash'
            }
        }
        $null = $PSBoundParameters.Remove('PartitionKey')
    }
    else
    {
        Write-Warning -Message $($LocalizedData.NonPartitionedCollectionWarning)
    }

    if ($PSBoundParameters.ContainsKey('IndexingPolicy'))
    {
        $bodyObject += @{
            indexingPolicy = $IndexingPolicy
        }
        $null = $PSBoundParameters.Remove('IndexingPolicy')
    }
    elseif ($PSBoundParameters.ContainsKey('IndexingPolicyJson'))
    {
        $bodyObject += @{
            indexingPolicy = ConvertFrom-Json -InputObject $IndexingPolicyJson
        }
        $null = $PSBoundParameters.Remove('IndexingPolicyJson')
    }

    if ($PSBoundParameters.ContainsKey('DefaultTimeToLive'))
    {
        $bodyObject += @{
            defaultTtl = $DefaultTimeToLive
        }
        $null = $PSBoundParameters.Remove('DefaultTimeToLive')
    }

    if ($PSBoundParameters.ContainsKey('UniqueKeyPolicy'))
    {
        $bodyObject += @{
            uniqueKeyPolicy = $UniqueKeyPolicy
        }
        $null = $PSBoundParameters.Remove('UniqueKeyPolicy')
    }

    $body = ConvertTo-Json -InputObject $bodyObject -Depth 20

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Post' `
        -ResourceType 'colls' `
        -Headers $headers `
        -Body $body

    $collection = ConvertFrom-Json -InputObject $result.Content

    if ($collection)
    {
        return (Set-CosmosDbCollectionType -Collection $collection)
    }
}
#EndRegion './Public/collections/New-CosmosDbCollection.ps1' 198
#Region './Public/collections/New-CosmosDbCollectionCompositeIndexElement.ps1' 0
function New-CosmosDbCollectionCompositeIndexElement
{

    [CmdletBinding()]
    [OutputType([CosmosDB.IndexingPolicy.CompositeIndex.Element])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateSet('Ascending', 'Descending')]
        [System.String]
        $Order = 'Ascending'
    )

    $element = New-Object -TypeName 'CosmosDB.IndexingPolicy.CompositeIndex.Element'
    $element.path = $Path
    $element.order = $Order.ToLower()

    return $element
}
#EndRegion './Public/collections/New-CosmosDbCollectionCompositeIndexElement.ps1' 25
#Region './Public/collections/New-CosmosDbCollectionExcludedPath.ps1' 0
function New-CosmosDbCollectionExcludedPath
{

    [CmdletBinding()]
    [OutputType([CosmosDB.IndexingPolicy.Path.ExcludedPath])]
    param
    (
        [Parameter()]
        [System.String]
        $Path = '/*'
    )

    $excludedPath = [CosmosDB.IndexingPolicy.Path.ExcludedPath]::new()
    $excludedPath.Path = $Path

    return $excludedPath
}
#EndRegion './Public/collections/New-CosmosDbCollectionExcludedPath.ps1' 18
#Region './Public/collections/New-CosmosDbCollectionIncludedPath.ps1' 0
function New-CosmosDbCollectionIncludedPath
{

    [CmdletBinding()]
    [OutputType([CosmosDB.IndexingPolicy.Path.IncludedPath])]
    param
    (
        [Parameter()]
        [System.String]
        $Path = '/*',

        [Parameter()]
        [CosmosDB.IndexingPolicy.Path.Index[]]
        $Index
    )

    if ($PSBoundParameters.ContainsKey('Index'))
    {
        $includedPath = [CosmosDB.IndexingPolicy.Path.IncludedPathIndex]::new()
        $includedPath.Path = $Path
        $includedPath.Indexes = $Index
    }
    else
    {
        $includedPath = [CosmosDB.IndexingPolicy.Path.IncludedPath]::new()
        $includedPath.Path = $Path
    }

    return $includedPath
}
#EndRegion './Public/collections/New-CosmosDbCollectionIncludedPath.ps1' 31
#Region './Public/collections/New-CosmosDbCollectionIncludedPathIndex.ps1' 0
function New-CosmosDbCollectionIncludedPathIndex
{

    [CmdletBinding()]
    [OutputType([CosmosDB.IndexingPolicy.Path.Index])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Hash', 'Range', 'Spatial')]
        [System.String]
        $Kind,

        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'Number', 'Point', 'Polygon', 'LineString')]
        [System.String]
        $DataType,

        [Parameter()]
        [Int32]
        $Precision
    )

    # Validate the path index parameters
    switch ($Kind)
    {
        'Hash'
        {
            <#
                Index Hask kind has been deprecated and will result in default Range indexes
                being created instead. Hash indexes will be removed in a future breaking
                release.
                See https://docs.microsoft.com/en-us/azure/cosmos-db/index-types#index-kind
            #>
            Write-Warning `
                -Message $($LocalizedData.WarningNewCollectionIncludedPathIndexHashDeprecated)

            if ($DataType -notin @('String', 'Number'))
            {
                New-CosmosDbInvalidArgumentException `
                    -Message $($LocalizedData.ErrorNewCollectionIncludedPathIndexInvalidDataType -f $Kind, $DataType, 'String, Number') `
                    -ArgumentName 'DataType'
            }
        }

        'Range'
        {
            if ($DataType -notin @('String', 'Number'))
            {
                New-CosmosDbInvalidArgumentException `
                    -Message $($LocalizedData.ErrorNewCollectionIncludedPathIndexInvalidDataType -f $Kind, $DataType, 'String, Number') `
                    -ArgumentName 'DataType'
            }
        }

        'Spatial'
        {
            if ($DataType -notin @('Point', 'Polygon', 'LineString'))
            {
                New-CosmosDbInvalidArgumentException `
                    -Message $($LocalizedData.ErrorNewCollectionIncludedPathIndexInvalidDataType -f $Kind, $DataType, 'Point, Polygon, LineString') `
                    -ArgumentName 'DataType'
            }

            if ($PSBoundParameters.ContainsKey('Precision'))
            {
                New-CosmosDbInvalidArgumentException `
                    -Message $($LocalizedData.ErrorNewCollectionIncludedPathIndexPrecisionNotSupported -f $Kind) `
                    -ArgumentName 'Precision'
            }
        }
    }

    $index = New-Object -TypeName ('CosmosDB.IndexingPolicy.Path.Index' + $Kind)
    $index.Kind = $Kind
    $index.DataType = $DataType

    if ($PSBoundParameters.ContainsKey('Precision'))
    {
        <#
            Index Precision should always be -1 for Range and must not be passed for Spatial.
            The Precision parameter will be removed in a future breaking release.
            See https://docs.microsoft.com/en-us/azure/cosmos-db/index-types#index-precision
        #>
        Write-Warning `
            -Message $($LocalizedData.WarningNewCollectionIncludedPathIndexPrecisionDeprecated)
    }

    return $index
}
#EndRegion './Public/collections/New-CosmosDbCollectionIncludedPathIndex.ps1' 90
#Region './Public/collections/New-CosmosDbCollectionIndexingPolicy.ps1' 0
function New-CosmosDbCollectionIndexingPolicy
{

    [CmdletBinding()]
    [OutputType([CosmosDB.IndexingPolicy.Policy])]
    param
    (
        [Parameter()]
        [System.Boolean]
        $Automatic = $true,

        [Parameter()]
        [ValidateSet('Consistent', 'Lazy', 'None')]
        [System.String]
        $IndexingMode = 'Consistent',

        [Parameter()]
        [CosmosDB.IndexingPolicy.Path.IncludedPath[]]
        $IncludedPath = @(),

        [Parameter()]
        [CosmosDB.IndexingPolicy.Path.ExcludedPath[]]
        $ExcludedPath = @(),

        [Parameter()]
        [CosmosDB.IndexingPolicy.CompositeIndex.Element[][]]
        $CompositeIndex = @(@())
    )

    if ($IndexingMode -eq 'None' -and $Automatic)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $($LocalizedData.ErrorNewCollectionIndexingPolicyInvalidMode) `
            -ArgumentName 'Automatic'
    }

    $indexingPolicy = [CosmosDB.IndexingPolicy.Policy]::new()
    $indexingPolicy.Automatic = $Automatic
    $indexingPolicy.IndexingMode = $IndexingMode
    $indexingPolicy.IncludedPaths = $IncludedPath
    $indexingPolicy.ExcludedPaths = $ExcludedPath
    $indexingPolicy.CompositeIndexes = $CompositeIndex

    return $indexingPolicy
}
#EndRegion './Public/collections/New-CosmosDbCollectionIndexingPolicy.ps1' 46
#Region './Public/collections/New-CosmosDbCollectionUniqueKey.ps1' 0
function New-CosmosDbCollectionUniqueKey
{

    [CmdletBinding()]
    [OutputType([CosmosDB.UniqueKeyPolicy.UniqueKey])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Path
    )

    $uniqueKey = [CosmosDB.UniqueKeyPolicy.UniqueKey]::new()
    $uniqueKey.paths = $Path

    return $uniqueKey
}
#EndRegion './Public/collections/New-CosmosDbCollectionUniqueKey.ps1' 18
#Region './Public/collections/New-CosmosDbCollectionUniqueKeyPolicy.ps1' 0
function New-CosmosDbCollectionUniqueKeyPolicy
{

    [CmdletBinding()]
    [OutputType([CosmosDB.UniqueKeyPolicy.Policy])]
    param
    (
        [Parameter(Mandatory = $true)]
        [CosmosDb.UniqueKeyPolicy.UniqueKey[]]
        $UniqueKey
    )

    $uniqueKeyPolicy = [CosmosDB.UniqueKeyPolicy.Policy]::new()
    $uniqueKeyPolicy.uniqueKeys = $UniqueKey

    return $uniqueKeyPolicy
}
#EndRegion './Public/collections/New-CosmosDbCollectionUniqueKeyPolicy.ps1' 18
#Region './Public/collections/Remove-CosmosDbCollection.ps1' 0
function Remove-CosmosDbCollection
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Alias('Name')]
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ })]
        [System.String]
        $Id
    )

    $null = $PSBoundParameters.Remove('Id')

    $null = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Delete' `
        -ResourceType 'colls' `
        -ResourcePath ('colls/{0}' -f $Id)
}
#EndRegion './Public/collections/Remove-CosmosDbCollection.ps1' 47
#Region './Public/collections/Set-CosmosDbCollection.ps1' 0
function Set-CosmosDbCollection
{

    [CmdletBinding(DefaultParameterSetName = 'ContextIndexPolicy')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ContextIndexPolicy')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ContextIndexPolicyJson')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'AccountIndexPolicy')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AccountIndexPolicyJson')]
        [ValidateScript({ Assert-CosmosDbAccountNameValid -Name $_ -ArgumentName 'Account' })]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateScript({ Assert-CosmosDbDatabaseIdValid -Id $_ -ArgumentName 'Database' })]
        [System.String]
        $Database,

        [Alias('Name')]
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Assert-CosmosDbCollectionIdValid -Id $_ })]
        [System.String]
        $Id,

        [Parameter(ParameterSetName = 'ContextIndexPolicy')]
        [Parameter(ParameterSetName = 'AccountIndexPolicy')]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.IndexingPolicy.Policy]
        $IndexingPolicy,

        [Parameter(ParameterSetName = 'ContextIndexPolicyJson')]
        [Parameter(ParameterSetName = 'AccountIndexPolicyJson')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $IndexingPolicyJson,

        [Parameter()]
        [ValidateRange(-1,2147483647)]
        [System.Int32]
        $DefaultTimeToLive,

        [Parameter()]
        [Switch]
        $RemoveDefaultTimeToLive,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [CosmosDB.UniqueKeyPolicy.Policy]
        $UniqueKeyPolicy
    )

    if ($PSBoundParameters.ContainsKey('DefaultTimeToLive') -and $RemoveDefaultTimeToLive.IsPresent)
    {
        New-CosmosDbInvalidArgumentException `
            -Message $LocalizedData.ErrorSetCollectionRemoveDefaultTimeToLiveConflict `
            -ArgumentName 'RemoveDefaultTimeToLive'
    }

    $headers = @{}

    $bodyObject = @{
        id = $id
    }

    $indexingPolicyIncluded = $false

    if ($PSBoundParameters.ContainsKey('IndexingPolicy'))
    {
        $ActualIndexingPolicy = $IndexingPolicy
        $indexingPolicyIncluded = $true
        $null = $PSBoundParameters.Remove('IndexingPolicy')
    }
    elseif ($PSBoundParameters.ContainsKey('IndexingPolicyJson'))
    {
        $ActualIndexingPolicy = ConvertFrom-Json -InputObject $IndexingPolicyJson
        $indexingPolicyIncluded = $true
        $null = $PSBoundParameters.Remove('IndexingPolicyJson')
    }

    $defaultTimeToLiveIncluded = $PSBoundParameters.ContainsKey('DefaultTimeToLive')
    $uniqueKeyPolicyIncluded = $PSBoundParameters.ContainsKey('UniqueKeyPolicy')

    $null = $PSBoundParameters.Remove('IndexingPolicy')
    $null = $PSBoundParameters.Remove('DefaultTimeToLive')
    $null = $PSBoundParameters.Remove('RemoveDefaultTimeToLive')
    $null = $PSBoundParameters.Remove('UniqueKeyPolicy')

    <#
        The partition key on an existing collection can not be changed.
        So to ensure an error does not occur, get the current collection
        and pass the existing partition key in the body.
    #>
    $existingCollection = Get-CosmosDbCollection @PSBoundParameters

    $null = $PSBoundParameters.Remove('Id')

    if ($indexingPolicyIncluded)
    {
        $bodyObject += @{
            indexingPolicy = $ActualIndexingPolicy
        }
    }
    else
    {
        $bodyObject += @{
            indexingPolicy = $existingCollection.indexingPolicy
        }
    }

    if ($existingCollection.partitionKey)
    {
        $bodyObject += @{
            partitionKey = $existingCollection.partitionKey
        }
    }

    if ($defaultTimeToLiveIncluded)
    {
        $bodyObject += @{
            defaultTtl = $DefaultTimeToLive
        }
    }
    elseif ($existingCollection.defaultTtl -and -not $RemoveDefaultTimeToLive)
    {
        $bodyObject += @{
            defaultTtl = $existingCollection.defaultTtl
        }
    }

    if ($uniqueKeyPolicyIncluded)
    {
        $bodyObject += @{
            uniqueKeyPolicy = $UniqueKeyPolicy
        }
    }
    elseif ($existingCollection.uniqueKeyPolicy)
    {
        $bodyObject += @{
            uniqueKeyPolicy = $existingCollection.uniqueKeyPolicy
        }
    }

    $body = ConvertTo-Json -InputObject $bodyObject -Depth 10

    $result = Invoke-CosmosDbRequest @PSBoundParameters `
        -Method 'Put' `
        -ResourceType 'colls' `
        -ResourcePath ('colls/{0}' -f $Id) `
        -Headers $headers `
        -Body $body

    $collection = ConvertFrom-Json -InputObject $result.Content

    if ($collection)
    {
        return (Set-CosmosDbCollectionType -Collection $collection)
    }
}
#EndRegion './Public/collections/Set-CosmosDbCollection.ps1' 176
#Region './Public/offers/Get-CosmosDbOffer.ps1' 0
function Get-CosmosDbOffer
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter()]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Query
    )

    if ($PSBoundParameters.ContainsKey('Id'))
    {
        $null = $PSBoundParameters.Remove('Id')

        $result = Invoke-CosmosDbRequest @PSBoundParameters `
            -Method 'Get' `
            -ResourceType 'offers' `
            -ResourcePath ('offers/{0}' -f $Id)

        $offer = ConvertFrom-Json -InputObject $result.Content
    }
    else
    {
        if (-not [System.String]::IsNullOrEmpty($Query))
        {
            $null = $PSBoundParameters.Remove('Query')

            # A query has been specified
            $headers += @{
                'x-ms-documentdb-isquery' = $True
            }

            # Set the content type to application/query+json for querying
            $null = $PSBoundParameters.Add('ContentType', 'application/query+json')

            # Create the body JSON for the query
            $bodyObject = @{ query = $Query }
            $body = ConvertTo-Json -InputObject $bodyObject

            $result = Invoke-CosmosDbRequest @PSBoundParameters `
                -Method 'Post' `
                -ResourceType 'offers' `
                -Headers $headers `
                -Body $body
        }
        else
        {
            $result = Invoke-CosmosDbRequest @PSBoundParameters `
                -Method 'Get' `
                -ResourceType 'offers'
        }

        $body = ConvertFrom-Json -InputObject $result.Content
        $offer = $body.Offers
    }

    if ($offer)
    {
        return (Set-CosmosDbOfferType -Offer $offer)
    }
}
#EndRegion './Public/offers/Get-CosmosDbOffer.ps1' 91
#Region './Public/offers/Get-CosmosDbOfferResourcePath.ps1' 0
function Get-CosmosDbOfferResourcePath
{

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id
    )

    return ('offers/{0}' -f $Id)
}
#EndRegion './Public/offers/Get-CosmosDbOfferResourcePath.ps1' 16
#Region './Public/offers/Set-CosmosDbOffer.ps1' 0
function Set-CosmosDbOffer
{

    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([Object])]
    param
    (
        [Alias('Connection')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Context')]
        [ValidateNotNullOrEmpty()]
        [CosmosDb.Context]
        $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'Account')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Account,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        $Key,

        [Parameter(ParameterSetName = 'Account')]
        [ValidateSet('master', 'resource')]
        [System.String]
        $KeyType = 'master',

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]
        $InputObject,

        [Parameter()]
        [ValidateSet('V1', 'V2')]
        [System.String]
        $OfferVersion,

        [Parameter()]
        [ValidateSet('S1', 'S2', 'S3', 'Invalid')]
        [System.String]
        $OfferType,

        [Parameter()]
        [ValidateRange(400, 250000)]
        [System.Int32]
        $OfferThroughput,

        [Parameter()]
        [System.Boolean]
        $OfferIsRUPerMinuteThroughputEnabled
    )

    begin {
        $invokeCosmosDbRequest = @{} + $PSBoundParameters
    }

    process {
        $null = $invokeCosmosDbRequest.Remove('InputObject')

        foreach ($object in $InputObject)
        {
            $bodyObject = @{
                '_rid'          = $object._rid
                id              = $object.id
                '_ts'           = $object._ts
                '_self'         = $object._self
                '_etag'         = $object._etag
                resource        = $object.resource
                offerType       = $object.offerType
                offerResourceId = $object.offerResourceId
                offerVersion    = $object.offerVersion
            }

            if ($PSBoundParameters.ContainsKey('OfferVersion'))
            {
                $null = $invokeCosmosDbRequest.Remove('OfferVersion')
                $bodyObject.offerVersion = $OfferVersion
            }

            if ($PSBoundParameters.ContainsKey('OfferType'))
            {
                $null = $invokeCosmosDbRequest.Remove('OfferType')
                $bodyObject.offerType = $OfferType
            }

            if ($bodyObject.offerVersion -eq 'V2')
            {
                <#
                    Setting the Offer Throughput and RU Per minute settings only
                    applicable for Offer Version V2
                #>
                $content = @{
                    offerThroughput = $object.Content.offerThroughput
                    offerIsRUPerMinuteThroughputEnabled = $object.Content.offerIsRUPerMinuteThroughputEnabled
                }

                if ($PSBoundParameters.ContainsKey('OfferThroughput'))
                {
                    $null = $invokeCosmosDbRequest.Remove('OfferThroughput')
                    $content.offerThroughput = $OfferThroughput
                }
                else
                {
                    if ($content.offerThroughput -lt 1000)
                    {
                        <#
                            If no offer throughput specified set to min for V2 of 400
                            However for partitioned collections minimum is 1000
                        #>
                        $content.offerThroughput = 1000
                    }
                }

                if ($PSBoundParameters.ContainsKey('OfferIsRUPerMinuteThroughputEnabled'))
                {
                    $null = $invokeCosmosDbRequest.Remove('OfferIsRUPerMinuteThroughputEnabled')
                    $content.offerIsRUPerMinuteThroughputEnabled = $OfferIsRUPerMinuteThroughputEnabled
                }

                $bodyObject += @{
                    content = $content
                }
            }

            $result = Invoke-CosmosDbRequest @invokeCosmosDbRequest `
                -Method 'Put' `
                -ResourceType 'offers' `
                -ResourcePath ('offers/{0}' -f $bodyObject.id) `
                -Body (ConvertTo-Json -InputObject $bodyObject)

            $offer = ConvertFrom-Json -InputObject $result.Content

            if ($offer)
            {
                (Set-CosmosDbOfferType -Offer $offer)
            }
        }
    }

    end {}
}
#EndRegion './Public/offers/Set-CosmosDbOffer.ps1' 142
#Region './suffix.ps1' 0
# Add Aliases
New-Alias -Name 'New-CosmosDbConnection' -Value 'New-CosmosDbContext' -Force
#EndRegion './suffix.ps1' 3
