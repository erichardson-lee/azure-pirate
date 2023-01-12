# Save-ServiceBusQueueMessage.psm1

function Save-ServiceBusQueueMessage
# save an individual file to a container in Azure Data Lake
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $QueueName,
        
        [Parameter(Mandatory = $true)]
        $Message
    )

    $ConnectionString = "$($env:ServiceBusConnectionStrSendOnly);EntityPath=$($QueueName)"
    # TODO review below timeout for token
    $TokenValidFor = 60 # seconds

    $Pattern = 'Endpoint=(.+);SharedAccessKeyName=(.+);SharedAccessKey=(.+);EntityPath=(.+)'
    ([uri]$Endpoint),$PolicyName,$Key,$Queue = ($ConnectionString -replace $Pattern,'$1;$2;$3;$4') -split ';'

    $UrlEncodedEndpoint = [System.Web.HttpUtility]::UrlEncode($Endpoint.OriginalString)
    $Expiry = [DateTimeOffset]::Now.ToUnixTimeSeconds() + $TokenValidFor
    $RawSignatureString = "$UrlEncodedEndpoint`n$Expiry"

    $HMAC = New-Object System.Security.Cryptography.HMACSHA256
    $HMAC.Key = [Text.Encoding]::ASCII.GetBytes($Key)
    $HashBytes = $HMAC.ComputeHash([Text.Encoding]::ASCII.GetBytes($RawSignatureString))
    $SignatureString = [Convert]::ToBase64String($HashBytes)
    $UrlEncodedSignatureString = [System.Web.HttpUtility]::UrlEncode($SignatureString)

    $SASToken = "SharedAccessSignature sig=$UrlEncodedSignatureString&se=$Expiry&skn=$PolicyName&sr=$UrlEncodedEndpoint"

    $Params = @{
        Uri = "https://$($Endpoint.Host)/$Queue/messages"
        ContentType = 'text/plain;charset=utf-8'
        Method = 'Post'
        Body = $Message
        Headers = @{
            'Authorization' = $SASToken
        }
    }

    $postMsg = Invoke-RestMethod @Params

}

Export-ModuleMember -Function Save-ServiceBusQueueMessage