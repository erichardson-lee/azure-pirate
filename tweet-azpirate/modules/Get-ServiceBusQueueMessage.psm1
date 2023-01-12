function Get-ServiceBusQueueMessage
{

    $ConnectionString = $env:SbusConnStr

    $TokenValidFor = 120

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
        Uri = "https://$($Endpoint.Host)/$($Queue)/messages/head"
        Method = 'Delete'
        Headers = @{
            'Authorization' = $SASToken
        }
    }

    return Invoke-RestMethod @Params -TimeoutSec 60

}

Export-ModuleMember -Function Get-ServiceBusQueueMessage