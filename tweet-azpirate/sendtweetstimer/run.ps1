# Input bindings are passed in via param block.
param($Timer)

$ErrorActionPreference = 'Continue'

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) 
{
    Write-Warning "Timer is running late!"
}

try 
{
    $Result = Get-ServiceBusQueueMessage
}
catch
{
    Write-Error "Could not connet to service bus. Error: $_"
}

if ($Result)
{
    Write-Host "Message received: $($Result)"

    try 
    {
        $tweet = Submit-TwitterMsg $Result
        Write-Host "Tweet sent ok with id: $($tweet.Id)"
    }
    catch
    {
        # put back to sbus queue
        Save-ServiceBusQueueMessage -Message $Result
        Write-Error "Could not send tweet. Error: $_"
    }
}
else
{
    Write-Host "NO MESSAGE RETURNED"
}

