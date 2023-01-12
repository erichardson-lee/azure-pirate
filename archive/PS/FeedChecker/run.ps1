# Input bindings are passed in via param block.
param($Timer)

$ErrorActionPreference = 'Continue'

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) 
{
    Write-Warning "Timer is running late!"
}

$testing = [System.Convert]::ToBoolean($env:localTesting)

if (!$env:hoursBack) { Write-Error "No time cap set" }

# download data file
try 
{
    $feedsUrl = "https://raw.githubusercontent.com/CloudDevDan/azure-pirate-rss/main/feeds.csv"
    (Invoke-webrequest -URI $feedsUrl).Content | out-file -filepath $env:localDataFile -Force
    Write-Host "Feeds file downloaded ok. Saved to: $($env:localDataFile)"
} 
catch 
{
    Write-Error "Could not download feeds file. Error: $($_)"
    exit
}

# import data file, then delete
try 
{
    $dataFile = import-csv -Path $env:localDataFile
    if (!$dataFile) { throw }
    Remove-Item $env:localDataFile -Force | Out-Null
    Write-Host "Feeds file imported ok. Local copy deleted."
} 
catch 
{
    Write-Error "Could not import feeds file. Error: $($_)"
    exit
}

# prevent duplication in $dataFile feed
$linksList = @()
$dataFile | ForEach {
    $linksList += $_.feed
}

$duplicateList = $linksList | select -unique
$duplicateCheck = Compare-object -referenceobject $linksList -differenceobject $duplicateList

if ($duplicateCheck.length -eq 1)
{
    Write-Error "Duplicate found in feeds.csv: $($duplicateCheck.InputObject)"
}
elseif ($duplicateCheck.length -ge 2)
{
    $duplicates = $duplicateCheck.InputObject
    Write-Error "Duplicates found in feeds.csv: $([string]$duplicates)"
    exit
}
else 
{
    Write-Host "No duplicate links found in in feeds.csv"
}

ForEach ($line in $dataFile) 
{

    $feed = $line.feed
    $name = $line.name
    $handle = $line.handle

    $Params = @{
        hoursBack = [int]$env:hoursBack;
        feed = $feed;
        name = $name;
        handle = $handle;
        testing = $testing;
    }

    Get-AllFeeds @Params

}
    


# catch 
# {
#     $e = $_.Exception
#     $line = $_.InvocationInfo.ScriptLineNumber
#     $msg = $e.Message
#     Write-Error "Error: '$($msg)' on line $($line)"
# }