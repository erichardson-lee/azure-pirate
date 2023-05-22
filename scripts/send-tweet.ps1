# Install-Module -Name BluebirdPS -Scope CurrentUser

. "$PSScriptRoot\env.ps1"

$ApiKey = ConvertTo-SecureString $env:TWITTER_CONSUMER_KEY  -AsPlainText -Force
$ApiSecret = ConvertTo-SecureString $env:TWITTER_CONSUMER_SECRET -AsPlainText -Force
$AccessToken = ConvertTo-SecureString $env:TWITTER_ACCESS_TOKEN -AsPlainText -Force
$AccessTokenSecret = ConvertTo-SecureString $env:TWITTER_ACCESS_SECRET -AsPlainText -Force

Set-TwitterAuthentication `
    -ApiKey $ApiKey `
    -ApiSecret $ApiSecret `
    -AccessToken $AccessToken `
    -AccessTokenSecret $AccessTokenSecret

$msg = "Ahoy Thar Swashbuckler!

New blog post from @ndteknik called: Azure Triumphs – S01E06 – Johan Åhlén & Magnus Mårtensson (livepod)

Check it out it here: https://url.azurepirate.com/s4e

#Azure #AzureFamily #CloudFamily #AzurePirate"

$msg

Publish-Tweet -TweetText $msg

# $PathToImage = "C:\Users\danm\Downloads\pirate.jpg"
# $MediaId = (Send-TwitterMedia -Path $PathToImage -Category TweetImage -AltImageText 'A Pirate').media_id

# Publish-Tweet `
#  -TweetText "Just making sure I can post images with the v2 Twitter API" `
#  -MediaId $MediaId


#  Publish-Tweet -TweetText "A new release of #BluebirdPS will soon be released. BluebirdPS is #PowerShell 7 Twitter automation client. Check it out! https://bit.ly/BluebirdPS"

# $msg = "Avast Ye!

# New blog post from @jackwesleyroper called: OpenShift vs. Kubernetes: What is the Difference?

# Check it out it here: https://url.azurepirate.com/sqr

# #Azure #AzureFamily #CloudFamily #AzurePirate"

# $msg = "Hit The Deck!

# New YouTube post from @NTFAQGuy called: Getting Started Creating Content

# Check it out it here: https://youtube.com/watch?v=_TGq7Q8QMYk

# #Azure #AzureFamily #CloudFamily #AzurePirate"

# $msgSplit = $msg.split('`n')
# ForEach ($line in $msgSplit) { 
#     $line
#     # if ($line -match 'youtube.com') {
#     #     $line
#     # }
# }


# if ($msg -match 'youtube.com')
# {
#     write "video post"
#     $url = $msg | select-string -AllMatches '(http[s]?|[s]?ftp[s]?)(:\/\/)([^\s,]+)' | %{ $_.Matches.value } 
#     $urlId = $url.Split('v=')[-1]
#     $imgUrl = "https://img.youtube.com/vi/$($urlId)/sddefault.jpg"
#     # D:\home\
#     Invoke-WebRequest $imgUrl -OutFile "C:\Users\danm\Downloads\sddefault.jpg"
    
# } else {
#     write "blog post"
# }