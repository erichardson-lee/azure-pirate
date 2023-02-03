using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$fileName = "posts.json"
$outPath = "/home/data/$($fileName)"
$ContainerName = "posts"

$Context = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage

Get-AzStorageBlobContent -Container $ContainerName -Blob $fileName -Context $Context -Destination $outPath -Force
$data = Get-Content -Path $outPath | ConvertFrom-Json
Remove-Item $outPath -Force

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $data
})