function New-Greeting {

    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $author,

        [Parameter(Mandatory = $true)]
        [string] $title,

        [Parameter(Mandatory = $true)]
        [string] $sUrl,

        [Parameter(Mandatory = $true)]
        [string] $handle

    )

    if ($sUrl -match 'youtube.com') 
    { 
        $type = "YouTube"
    }
    else
    {
        $type = "blog"
    }

    $greetings = @(
        "Aaaarrrrgggghhhh!"
        "Abandon Ship!"
        "Ahoy Landlubber!"
        "Ahoy Me Hearties!"
        "Ahoy Me Hearties!"
        "Ahoy Thar Swashbuckler!"
        "Ahoy!"
        "Avast Ye Scallywag!"
        "Avast Ye!"
        "Aye Aye!"
        "Aye, Aye Captain!"
        "Batten down the hatches!"
        "Blimey!"
        "Blow me down!"
        "Fire in the hole!"
        "Heave Ho!"
        "Heave Ho!"
        "Hit The Deck!"
        "Land Ho!"
        "Shiver Me Timbers!"
        "Thar She Blows!"
        "Walk The Plank!"
        "Walk The Plank!"
        "Yarr!"
        "Yo Ho Ho!"
        "Yo Ho Ho!"
    )

    $greeting = $greetings | Get-Random

    if ($handle -eq "@azure_projects_")
    {
        $message = "Ahoy!`n`nAZURE PROJECTS has a new post called: $($title)`n`nCheck it out it here: $($sUrl)`n`n#Azure #CloudFamily"
        if ([string]$message.Length -gt 276) {
            $message = "Ahoy!`n`nAZURE PROJECTS has a new post!`n`nCheck it out it here: $($sUrl)`n`n#Azure #CloudFamily"
        }
        return $message
    }
    else
    {
        if ($title -eq "NA")
        {
            $message = "$($greeting)`n`nNew $($type) post from $($handle)!`n`nCheck it out it here: $($sUrl)`n`n#Azure #AzureFamily #CloudFamily #AzurePirate"
        }
        else 
        {
            $message = "$($greeting)`n`nNew $($type) post from $($handle) called: $($title)`n`nCheck it out it here: $($sUrl)`n`n#Azure #AzureFamily #CloudFamily #AzurePirate"
        }

        if ([string]$message.Length -gt 276) {
            return "Yarr! New $($type) post from $($handle)'.`n`nCheck it out it here: $($sUrl)"
        } else {
            return $message
        }
    }
}

Export-ModuleMember -Function New-Greeting