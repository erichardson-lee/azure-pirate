using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$fileName = "posts.json"
$outPath = "D:\home\$($fileName)"
# $outPath = "C:\Users\danm\Git\azure-pirate\apis-azpirate\getpoststimer\$($fileName)"
$ContainerName = "posts"

$Context = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage

$getData = Get-AzStorageBlob -Blob $fileName -Container $ContainerName -Context $Context
$data = $getData.ICloudBlob.DownloadText()

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $data
})
