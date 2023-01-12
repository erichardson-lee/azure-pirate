function New-Markdown {

    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$origUrl,

        [Parameter(Mandatory = $true)]
        [string]$author,

        [Parameter(Mandatory = $true)]
        [string]$authorCleaned,

        [Parameter(Mandatory = $true)]
        [string]$title,

        [Parameter(Mandatory = $true)]
        [string]$date,

        [Parameter(Mandatory = $true)]
        [string]$handle,

        [Parameter(Mandatory = $false)]
        [ValidateSet("blog","YouTube")]
        [string] $type = "blog"
    )

    Write-Host "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"

    if ($type -eq 'blog') {
        try 
        {
            $request = Invoke-RestMethod $origUrl -TimeoutSec 20 -StatusCodeVariable "scv"
        }
        catch
        {
            Write-Warning "Could not connect to $($author)'s page: $($origUrl). Error: $($_) Skipping..."
            return
        }

        $content = $request.Split("")

        $content | ForEach-Object {
            if ($_ -match 'twitter:image') { 
                $imageUrl = ((Select-String '(http[s]?)(:\/\/)([^\s,]+)(?=")' -Input $_).Matches.Value)
                break
            }
        }
    }

    # $greetingPrep = $greeting.Replace("@","https://twitter.com/").Replace("Check it out it here: ").Replace("`n`n#Azure #AzureFamily #CloudFamily #AzurePirate","")
    # Write-Warning $greetingPrep

    $titleCleaned = (Remove-StringSpecialCharacter -String $title -SpecialCharacterToKeep " ").Replace(" ","-")
    $datePrep = $date.Replace("/","-")
    $fileName = ("$($datePrep)-$($authorCleaned)-$($titleCleaned)").ToLower()
    $file = "C:\Users\danm\Git\azure-pirate\PS\Posts\$($fileName).md"

    Write-Warning $file

    # if file exists handle
    if (Test-Path $file) { Remove-Item $file -Force }

    "---" | Out-File -FilePath $file -Append -Force
    "layout: post" | Out-File -FilePath $file -Append -Force
    "title: `"$($title)`"" | Out-File -FilePath $file -Append -Force
    # "tags: [Azure]" | Out-File -FilePath $file -Append -Force
    "excerpt_separator: <!--more-->" | Out-File -FilePath $file -Append -Force

    if ($imageUrl) {
        "featured_image_thumbnail: $($imageUrl)" | Out-File -FilePath $file -Append -Force
        "featured_image: $($imageUrl)" | Out-File -FilePath $file -Append -Force
    }

    "date: $($date)" | Out-File -FilePath $file -Append -Force

    "---`n" | Out-File -FilePath $file -Append -Force

    $greetings = Get-Content greetings.txt
    if (!$greetings) { Write-Error "Could not read from greetings.txt"; return }
    $greeting = $greetings | Get-Random

    if ($type -eq 'blog') {
        
        $message = "$($greeting) New $($type) post from <a href=`"https://twitter.com/$($handle)`" target=_blank>$($handle)</a> called: $($title)`n`n<a href=`"$($origUrl)`" target=_blank>Check it out it here!</a>"
        
        $message | Out-File -FilePath $file -Append -Force
    }

    if ($type -eq 'YouTube') {

        $message = "$($greeting) New $($type) post from <a href=`"https://twitter.com/$($handle)`" target=_blank>$($handle)</a>. Check it out it below:`n"
        
        $message | Out-File -FilePath $file -Append -Force

        $position = $origUrl.IndexOf("=")
        $pos = $origUrl.Substring($position+1) 

        "<iframe width=`"560`" height=`"315`" src=`"https://www.youtube.com/embed/$($pos)`" title=`"YouTube video player`" frameborder=`"0`" allow=`"accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share`" allowfullscreen></iframe>" | Out-File -FilePath $file -Append -Force
    }

    Write-Host "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO"

    # save to storage account
    # delete local file
    # workflow to take storage file and commit to repo

}

Export-ModuleMember -Function New-Markdown

# https://www.youtube.com/watch?v=nJSxRqJ2kgQ

# <iframe width="560" height="315" src="https://www.youtube.com/embed/isipCegzF2M" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>