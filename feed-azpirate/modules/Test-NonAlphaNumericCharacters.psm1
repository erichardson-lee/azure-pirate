function Test-ForeignCharacters {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )

    $pattern = '[^\p{IsBasicLatin}]'
    $match = $InputString -match $pattern

    return [bool]$match
}

Export-ModuleMember -Function Test-ForeignCharacters

