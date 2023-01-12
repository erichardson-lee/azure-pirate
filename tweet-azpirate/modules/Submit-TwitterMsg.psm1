function Submit-TwitterMsg {

    Param
    (
        
        [Parameter(Mandatory = $true)]
        $Message
    )

    $ApiKey = ConvertTo-SecureString $env:TwitterApiKey  -AsPlainText -Force
    $ApiSecret = ConvertTo-SecureString $env:TwitterApiSecret -AsPlainText -Force
    $AccessToken = ConvertTo-SecureString $env:TwitterAccessToken -AsPlainText -Force
    $AccessTokenSecret = ConvertTo-SecureString $env:TwitterAccessTokensecret -AsPlainText -Force
    
    Set-TwitterAuthentication `
        -ApiKey $ApiKey `
        -ApiSecret $ApiSecret `
        -AccessToken $AccessToken `
        -AccessTokenSecret $AccessTokenSecret | Out-Null
    
    if ($Message -match 'youtube.com')
    {

        Write-Host "Working with a YouTube post..."
        # extract url from message
        $url = $Message | select-string -AllMatches '(http[s]?|[s]?ftp[s]?)(:\/\/)([^\s,]+)' | %{ $_.Matches.value } 
        # get the video id + form thumbnail url
        $urlId = $url.Split('v=')[-1]
        $imgUrl = "https://img.youtube.com/vi/$($urlId)/sddefault.jpg"
        # download the file locally
        Remove-Item $env:localDataFile -ErrorAction SilentlyContinue # delete if already exist for whatever reason
        # Write-Host "Saving to: $($env:localDataFile)"
        try {
            Invoke-WebRequest $imgUrl -OutFile $env:localDataFile
            # upload to twitter and get ID
            $MediaId = (Send-TwitterMedia -Path $env:localDataFile -Category TweetImage -AltImageText "Thumbnail for $($url)").media_id
            Remove-Item $env:localDataFile
            return Publish-Tweet -TweetText $Message -MediaId $MediaId
        }
        catch
        {
            Write-Host "Could not generate thumb, so posting as text only"
            return Publish-Tweet -TweetText $Message
        }

    } else {

        Write-Host "Working with a blog post..."
        return Publish-Tweet -TweetText $Message
        
    }
}

Export-ModuleMember -Function Submit-TwitterMsg