function Get-AllFeeds {

    Param
    (
        [Parameter(Mandatory = $true)]
        [int] $hoursBack,
        
        [Parameter(Mandatory = $true)]
        [string] $feed,

        [Parameter(Mandatory = $true)]
        [string] $name,

        [Parameter(Mandatory = $true)]
        [string] $handle,

        [Parameter(Mandatory = $false)]
        [bool] $testing = $false

    )

    try 
    {
        $request = Invoke-RestMethod $feed -TimeoutSec 80 -StatusCodeVariable "scv"
        Write-Host "Pulling feed for: $($name). Feed: $($feed). Status: $($scv)"
    }
    catch
    {
        Write-Warning "Could not connect to $($name)'s feed: $($feed). Status: $($scv). Skipping..."
        return
    }
    
    $posts = $request | where { {try {$_.SelectSingleNode('link')} catch{$null} -ne $null} }

    if (!$posts) { Write-Warning "No posts found for feed: $($($feed)). Skipping..."; continue }

    ForEach ($post in $posts) 
    {

        # get post date
        if ($post.PubDate) { $date = $post.PubDate }
        elseif ($post.published) { $date = $post.published }
        else { Write-Warning "No dates found in feed $($feed). Skipping..."; continue }

        # convert post date to datetime obj
        try 
        {
            $postDate = Get-Date $date
        } catch 
        {
            try 
            {
                $postDate = Get-Date $date.Substring(0, $date.LastIndexOf(' ')) # handling for datetime with timezones
            } 
            catch 
            {
                Write-Error "Could not work with date: $($date). Error: $($_). Skipping"
                continue
            }
        }

        # check if date within expected range
        if ($postDate -lt (Get-Date).AddHours($hoursBack))
        { 
            continue # not within expected range - skip
        } else 
        {
            $postDateFmt = Get-Date $postDate -Format "yyyy-MM-dd"
            Write-Host "Found a new post from $($handle). Posted on: $($postDateFmt)."
        }

        # get the post title + clean up
        if ($post.title.getType().Name -ne 'String')
        {
            if ($post.title."#cdata-section" -and $post.title."#cdata-section".getType().Name -eq 'String')
            {
                $title =  $post.title."#cdata-section"
            }
            else { $title = "NA" }
        }
        else { $title = $post.title }

        if (!$post.title) { $title = "NA" }
        if (!$title) { Write-Warning "Could not get the title for this post. Using 'NA'" }

        $title = $title.Trim().Replace('“','"').Replace('”','"') # nice and tidy title

        # get the post link
        if ($feed -match 'youtube.com')
        { 
            $link = "https://www.youtube.com/watch?v=$($post.videoId)" 
        }
        else
        {
            if ($post.link -match "http"){ $link = $post.link }
            elseif ($post.link.href -match "http") { $link = $post.link.href }
            elseif ($post.id -match "http") { $link = $post.id }
            else { Write-Warning "Could not get post link. Skipping..."; continue }
        }

        # clean up string for DB entry
        try 
        {
            $authorCleaned = Remove-StringSpecialCharacter -String $name
            $titleCleaned = Remove-StringSpecialCharacter -String $title
        }
        catch
        {
            Write-Error "Could not clean strings. Stopping. Error: $_"
        }

        # DB lookup
        try 
        {
            $SecureKey = ConvertTo-SecureString $env:CosmosAccountKey -AsPlainText -Force
            $cosmosDbContext = New-CosmosDbContext -Account $env:CosmosAccountName -Database $env:CosmosDBName -Key $SecureKey
            $query = "SELECT * FROM logs c WHERE (c.author = '$($authorCleaned)') AND (c.titleCleaned = '$($titleCleaned)')"
            $record = Get-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:CosmosCollectionName -Query $query -QueryEnableCrossPartition $True
            Write-Verbose "DB query: $($query)"
        }
        catch
        {
            Write-Error "Could not work with Cosmos. Stopping. Error: $_"
            exit
        }

        if ($record)
        {
            Write-Host "Record already exists from $($handle) called: $($title). Skipping..."
            continue
        }
        else 
        {
            if ($testing -eq $false)
            {

                try 
                {
                    if ($link -match 'youtube.com') 
                    { 
                        $sUrl = $link # maintain youtube.com url for later image extract
                    }
                    else
                    {
                        $sUrl = New-ShortURL -url $link # shorten url with custom domain
                    }
                    
                }
                catch
                {
                    Write-Warning "Could not shorten URL. Skipping... Error: $_"
                    $sUrl = $link
                }
                
                try 
                {
                    $greeting = New-Greeting -author $name -title $title -sUrl $sUrl -handle $handle
                }
                catch
                {
                    Write-Error "Could not create greeting. Stopping. Error: $_"
                    exit
                }
        
                $hash = [ordered]@{
                    id = "$([Guid]::NewGuid().ToString())";
                    date = $postDateFmt;
                    author = $authorCleaned;
                    handle = $handle;
                    titleCleaned = $titleCleaned;
                    url = $sUrl;
                    origUrl = $postURL;
                    greeting = $greeting;
                }

                Write-Host ">>> CREATING A NEW ENTRY:`n$($greeting)."

                try
                {
                    Write-Host "Record does not yet exist. Creating..."
                    $message = $hash | ConvertTo-Json -Depth 4
                    $doc = New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:CosmosCollectionName -DocumentBody $message -PartitionKey $postDateFmt
                    Write-Host "Record created."

                }
                catch
                {
                    $hash.GetEnumerator().ForEach({ "$($_.Name)=$($_.Value)" })
                    Write-Error "Could not write record to Cosmos DB. Stopping. Error: $_"
                    exit
                }

                try
                {
                    Write-Host "Pushing to Azure Service Bus Queue..."
                    Save-ServiceBusQueueMessage -Message $greeting
                }
                catch
                {
                    Write-Error "Could not push message to Service Bus. Stopping. Error: $_"
                }
            
            }
        }
    }
}

Export-ModuleMember -Function Get-AllFeeds