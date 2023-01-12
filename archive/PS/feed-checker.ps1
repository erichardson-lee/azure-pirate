$ErrorActionPreference = 'Continue'

ForEach ($file in Get-ChildItem -Path "$PSScriptRoot/Modules" -Filter *.psm1 -Recurse){
    Import-Module $file.fullname -Force
    Write-Host "Imported module: $($file.fullname)"
}

$hoursBack=[int]-1000 # the number of hours back you want articles from

$dataFile = import-csv -Path 'feeds.csv'

# prevent duplication in $dataFile feed
$linksList = @()
$dataFile | ForEach {
    $linksList += $_.feed
}

$duplicateList = $linksList | select –unique

$duplicateCheck = Compare-object –referenceobject $linksList –differenceobject $duplicateList

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

try {
    
    $dataFile | ForEach {

        $feed = $_.feed
        $name = $_.name
        $handle = $_.handle

        $Params = @{
            hoursBack = $hoursBack;
            feed = $feed;
            name = $name;
            handle = $handle;
            testing = $true;
        }
        
        Search-BlogFeed @Params

        # if ($feed -match 'youtube.com')
        # {
        #     Search-YTFeed @Params
        # }
        # else
        # {
        #     Search-BlogFeed @Params
        # }

    }
    
}
catch {
    $e = $_.Exception
    $line = $_.InvocationInfo.ScriptLineNumber
    $msg = $e.Message
    Write-Error "Error: '$($msg)' on line $($line)"
}