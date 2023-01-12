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

    $greetings = "Yarr!", 
        "Ahoy!", 
        "Aye, Aye Captain!", 
        "Avast Ye!", 
        "Shiver Me Timbers!", 
        "Yo Ho Ho!", 
        "Walk The Plank!", 
        "Ahoy Me Hearties!",
        "Blimey!",
        "Heave Ho!",
        "Ahoy Landlubber!",
        "Thar She Blows!",
        "Hit The Deck!",
        "Yo Ho Ho!",
        "Avast Ye Scallywag!",
        "Walk The Plank!",
        "Ahoy Me Hearties!",
        "Ahoy Thar Swashbuckler!",
        "Aaaarrrrgggghhhh!",
        "Aye Aye!",
        "Blow me down!",
        "Heave Ho!"

    $greeting = $greetings | Get-Random

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

Export-ModuleMember -Function New-Greeting