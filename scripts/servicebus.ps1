# $serviceBussInstalled = Get-InstalledModule Az.ServiceBus
# if (!$serviceBussInstalled) {
#     Install-Module Az.ServiceBus
# }

. "$PSScriptRoot\env.ps1"

function Get-SBusToken {
    $token = $env:sbustoken

    $ConnectionString = "$($token)"

    $TokenValidFor = 3600

    # This part may need editing, EntityPath is specific to connection strings from policies on a queue level
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

    return @{
        Endpoint = $Endpoint.Host;
        Queue = $Queue;
        SASToken = $SASToken;
    }

}

# POPULATE WITH DUMMY MESSAGES
# $dummyMessages = @("rtrth","ttetert","bfgbfg","www","ggggg")

$dummyMessages = @()
1..10 | % { $dummyMessages += Get-Random }

$t = Get-SBusToken
foreach ($message in $dummyMessages) {
    $Params = @{
        Uri = "https://$($t.Endpoint)/$($t.Queue)/messages"
        ContentType = 'text/plain;charset=utf-8'
        Method = 'Post'
        Body = $message
        Headers = @{
            'Authorization' = $t.SASToken
        }
    }
    Invoke-WebRequest @Params | Out-Null
    Write-Host "Sent: $($message)"
}


# Receive and Delete Message (Destructive Read)
# https://learn.microsoft.com/en-us/rest/api/servicebus/receive-and-delete-message-destructive-read
$t = Get-SBusToken
$Params = @{
    Uri = "https://$($t.Endpoint)/$($t.Queue)/messages/head"
    ContentType = 'text/plain;charset=utf-8'
    Method = 'Delete'
    Headers = @{
        'Authorization' = $t.SASToken
    }
}
# locked for 5 mins
$Result = Invoke-WebRequest @Params
$Result.Content

($Result.Headers.BrokerProperties | ConvertFrom-Json).MessageId
$Result.Headers.BrokerProperties | ConvertFrom-Json


# # Peek-Lock Message (Non-Destructive Read)
# # https://learn.microsoft.com/en-us/rest/api/servicebus/peek-lock-message-non-destructive-read
# $t = Get-SBusToken
# $Params = @{
#     Uri = "https://$($t.Endpoint)/$($t.Queue)/messages/head"
#     ContentType = 'text/plain;charset=utf-8'
#     Method = 'Post'
#     Headers = @{
#         'Authorization' = $t.SASToken
#     }
# }
# # locked for 5 mins
# $Result = Invoke-WebRequest @Params
# $Result.Content

# ($Result.Headers.BrokerProperties | ConvertFrom-Json).MessageId
# $Result.Headers.BrokerProperties | ConvertFrom-Json









# Receive one
# $Params = @{
#     Uri = "https://$($Endpoint.Host)/$Queue/messages/head"
#     ContentType = 'text/plain;charset=utf-8'
#     Method = 'Post'
#     Headers = @{
#         'Authorization' = $SASToken
#     }
# }

# Receive and Delete
# $Params = @{
#     Uri = "https://$($Endpoint.Host)/$Queue/messages/head"
#     ContentType = 'text/plain;charset=utf-8'
#     Method = 'Delete'
#     Headers = @{
#         'Authorization' = $SASToken
#     }
# }

# $r = Invoke-RestMethod @Params -StatusCodeVariable "scv" -ResponseHeadersVariable "aa"
# $r
# Write-Host "StatusCodeVariable: $($scv)"
# Write-Host "ResponseHeadersVariable: $($aa)"

# $aa

