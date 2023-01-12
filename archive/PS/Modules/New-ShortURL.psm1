function New-ShortURL {

    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $url

    )

    $code = $env:short-url-func-key

    $func = "https://url.azurepirate.com/api/UrlShortener?code=$($code)"

    #CREATE new ShortURL
    $Body = @{
        title = "Microsoft"
        url = $url
        vanity = ""
    }

    $Parameters = @{
        Method = "POST" 
        Uri =  $func
        Body = ($Body | ConvertTo-Json)
        ContentType = "application/json"
    }

    # TODO error handling

    $newUrl = Invoke-RestMethod @Parameters
    return $newUrl.ShortUrl

}

Export-ModuleMember -Function New-ShortURL