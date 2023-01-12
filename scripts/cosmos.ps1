# . env.ps1

. "$PSScriptRoot\env.ps1"

# query
$SecureKey = ConvertTo-SecureString $env:CosmosAccountKey -AsPlainText -Force
$cosmosDbContext = New-CosmosDbContext -Account $env:CosmosAccountName -Database $env:CosmosDBName -Key $SecureKey
$query = "SELECT * FROM c"
$record = Get-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:CosmosCollectionName -Query $query -QueryEnableCrossPartition $True
$record.length

$SecureKey = ConvertTo-SecureString $env:NewCosmosAccountKey -AsPlainText -Force
$cosmosDbContext = New-CosmosDbContext -Account $env:NewCosmosAccountName -Database $env:NewCosmosDBName -Key $SecureKey

$count = $record.length

ForEach ($r in $record)
{
    $postDateFmt = Get-Date $r.date -Format "yyyy-MM-dd"

    $newHash = [ordered]@{
        id = $r.id
        date = $postDateFmt
        author = $r.author
        handle = $r.handle
        title = $r.title
        titleCleaned = $r.titleCleaned
        url = $title.url
        greeting = $title.greeting
    }

    $message = $newHash | ConvertTo-Json -Depth 4
    $doc = New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:NewCosmosCollectionName -DocumentBody $message -PartitionKey $postDateFmt

    # Start-Sleep 15
    
    $count = $count -1
    Write-Host "Working with $($count) items"

}