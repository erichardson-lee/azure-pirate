# . env.ps1

. "$PSScriptRoot\env.ps1"

$SecureKey = ConvertTo-SecureString $env:NewCosmosAccountKey -AsPlainText -Force
$cosmosDbContext = New-CosmosDbContext -Account $env:NewCosmosAccountName -Database $env:NewCosmosDBName -Key $SecureKey
$query = "SELECT * FROM logs c WHERE c.handle = `"@kaylumah`""
$record = Get-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:NewCosmosCollectionName -Query $query -QueryEnableCrossPartition $True # -MaxItemCount 5 # -ReturnJson

# ForEach ($r in $record) {
#     $r.author
# }

# $t = $record[-1].author

$name = "Max Hamulyák" #-replace "å","a" -replace "á","a"

# $enc = [System.Text.Encoding]::UTF8.GetBytes("á")

# # $test = [System.Text.Encoding]::UTF8.GetString($enc)

# # $test = [System.Text.Encoding]::ASCII.GetString($enc)

# $test = [System.Text.Encoding]::Default.GetString($enc)

$postDateFmt = Get-Date -Format "yyyy-MM-dd"

$hash = [ordered]@{
    id = "$([Guid]::NewGuid().ToString())";
    date = $postDateFmt;
    author = $name;
    handle = "@kaylumah";
}

$message = $hash | ConvertTo-Json -Depth 4 | out-file "test.json" -encoding ascii

$message = Get-Content "test.json" | ConvertTo-Json -encoding ascii

New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:NewCosmosCollectionName -DocumentBody $message -PartitionKey $postDateFmt




# encode $name to utf8
# $utf8 = [System.Text.Encoding]::UTF8.GetBytes($name)

# if ($record)
# {
#     $filtered = $record | Sort-Object date -Descending | select -first 10 | select handle, date, url, greeting #| ConvertTo-Json
#     ForEach ($r in $filtered)
#     {
#         if (!$r.title)
#         {
#             Write-Warning "This record has no title. Pulling it from greeting."
#             if ($r.greeting -and $r.greeting -match "called:")
#             {
#                 $newTitle = $r.greeting.Split("called")[1].Split("Check it out it here")[0].Replace(": ","").Replace("`n","")
#                 $r | Add-Member -Membertype NoteProperty -Name title -value $newTitle -Force
#             } else {
#                 Write-Warning "This record has no title or usable greeting. ID: $($r.id). Skipping,"
#                 continue
#             }
#         }
#     }
# } else {
#     Write-Error "No records returned. Stopping."
#     exit
# }

# $filtered | select handle, date, url, title | ConvertTo-Json


# $filtered = $record | Sort-Object date -Descending | select -first 10 | select handle, date, url, greeting | ConvertTo-Json
# ForEach ($r in $filtered)
# {
#     if (!$r.title)
#     {
#         if ($r.greeting)
#         {

#         }
#     }
#         $newTitle = $r.greeting.Split("called")[1].Split("Check it out it here")[0].Replace(": ","").Replace("`n","")
    
# }

# # if ($record)
# # {
# #     $filtered = $record | Sort-Object date | select handle, date, url, greeting | ConvertTo-Json
# #     ForEach ($r in $filtered)
# #     {
# #         if (!$r.title)
# #         {
# #             Write-Warning "This record has no title. Pulling it from greeting."
# #             if ($r.greeting)
# #             {
# #                 $r.greeting
# #             } else {
# #                 $r
# #                 Write-Error "This record has no title or greeting. ID: $($r.id) Pulling it from greeting."
# #             }
# #             # $r | ConvertTo-Json
# #         }
# #     }
# # } else {
# #     Write-Error "No records returned. Stopping."
# #     exit
# # }

# # $x = $record.greeting | select -last 1

# # $x.Split("called")[1].Split("Check it out it here")[0].Replace(": ","").Replace("`n","")

# # $record.greeting

# # $record | Sort-Object date | select -last 5 | select handle, date, url, greeting | ConvertTo-Json

# # $record.count


# # sort out no url
# # sort out no title

# ForEach ($r in $record)
# {
#     if ($r.greeting -match "called:" -and !$r.title)
#     {

#         # $r
#         # $r | Add-Member -Membertype NoteProperty -Name Computername -value "dd" -Force
#         # $r.Computername
#         $newTitle = $r.greeting.Split("called")[1].Split("Check it out it here")[0].Replace(": ","").Replace("`n","")
#         $newTitle

#         $r | Add-Member -Membertype NoteProperty -Name title -value $newTitle -Force
#         $r | ConvertTo-Json

#         # # $x = $r | ConvertTo-Json | ConvertFrom-Json
#         # # $r["title"] = "TEST"
#         # $r.GetType()

#         # $x = $r | ConvertFroom-Json

#         # $r.title = $newTitle
#         # $r

#         # $hash = [ordered]@{
#         #     id = $r.id
#         #     date = $r.date;
#         #     author = $r.author;
#         #     handle = $r.handle;
#         #     title = $newTitle;
#         #     titleCleaned = $r.titleCleaned;
#         #     url = $r.url;
#         #     origUrl = $r.origUrl;
#         #     greeting = $r.greeting;
#         # }

#        #  New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:NewCosmosCollectionName -DocumentBody $r -PartitionKey $r.date

#         Set-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:NewCosmosCollectionName -Id $r.id -DocumentBody $r -PartitionKey $r.date
#         return
#     }
# }






# # called: A couple of announcements...\n\n

# # $record | Limit 2 | ConvertTo-Json
# # $record | Sort -Descending | ConvertTo-Json

# # query
# # $SecureKey = ConvertTo-SecureString $env:CosmosAccountKey -AsPlainText -Force
# # $cosmosDbContext = New-CosmosDbContext -Account $env:CosmosAccountName -Database $env:CosmosDBName -Key $SecureKey
# # $query = "SELECT * FROM c"
# # $record = Get-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:CosmosCollectionName -Query $query -QueryEnableCrossPartition $True
# # $record.length

# # $SecureKey = ConvertTo-SecureString $env:NewCosmosAccountKey -AsPlainText -Force
# # $cosmosDbContext = New-CosmosDbContext -Account $env:NewCosmosAccountName -Database $env:NewCosmosDBName -Key $SecureKey

# # $count = $record.length

# # ForEach ($r in $record)
# # {
# #     $postDateFmt = Get-Date $r.date -Format "yyyy-MM-dd"

# #     $newHash = [ordered]@{
# #         id = $r.id
# #         date = $postDateFmt
# #         author = $r.author
# #         handle = $r.handle
# #         title = $r.title
# #         titleCleaned = $r.titleCleaned
# #         url = $title.url
# #         greeting = $title.greeting
# #     }

# #     $message = $newHash | ConvertTo-Json -Depth 4
# #     $doc = New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $env:NewCosmosCollectionName -DocumentBody $message -PartitionKey $postDateFmt

# #     # Start-Sleep 15
    
# #     $count = $count -1
# #     Write-Host "Working with $($count) items"

# # }





# # https://learn.microsoft.com/en-us/azure/cosmos-db/nosql/manage-with-powershell

# $subscriptionName = "Visual Studio Enterprise Subscription - MCT"

# Connect-AzAccount -Subscription $subscriptionName

# $resourceGroupName = "myResourceGroup"
# $location = "UK South"
# $accountName = "mycosmosaccount"
# $apiKind = "Sql"
# $databaseName = "mydatabase"
# $containerName = "mycontainer"
# $partitionKeyPath = "/id"
# $throughput = 400 #minimum = 400

# New-AzResourceGroup -Name $resourceGroupName -Location $location

# New-AzCosmosDBAccount `
#     -Name $accountName `
#     -ResourceGroupName $resourceGroupName `
#     -Location $location `
#     -ApiKind $apiKind

# New-AzCosmosDBSqlDatabase `
#     -ResourceGroupName $resourceGroupName `
#     -AccountName $accountName `
#     -Name $databaseName    
    
# New-AzCosmosDBSqlContainer `
#     -ResourceGroupName $resourceGroupName `
#     -AccountName $accountName `
#     -DatabaseName $databaseName `
#     -Name $containerName `
#     -PartitionKeyKind Hash `
#     -PartitionKeyPath $partitionKeyPath `
#     -Throughput $throughput

# $key = (Get-AzCosmosDBAccountKey `
#     -ResourceGroupName $resourceGroupName `
#     -Name $accountName `
#     -Type "Keys").PrimaryMasterKey

# $requiredPSModules = "Az", "CosmosDB"

# ForEach ($module in $requiredPSModules)
# {
#     if (-not(Get-Module -ListAvailable -Name $module)) {
#         Install-Module $module
#         Import-Module $module # Might not be needed
#     }
# }

# $document = [ordered]@{
#     id           = "$([Guid]::NewGuid().ToString())";
#     name         = "Dan";
#     location     = "Ripon";
# }

# 0..9 | Foreach-Object {
#     $id = $([Guid]::NewGuid().ToString())
#     $document = @"
# {
#     `"id`": `"$id`",
#     `"content`": `"Some string`",
#     `"more`": `"Some other string`"
# }
# "@
#     New-CosmosDbDocument -Context $cosmosDbContext -CollectionId $containerName -DocumentBody $document -PartitionKey $id
# }
