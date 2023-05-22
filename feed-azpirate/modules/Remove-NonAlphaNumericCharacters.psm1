function Remove-NonAlphaNumericCharacters {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )

    # Define a regular expression pattern to match non-alphanumeric characters
    $pattern = '[^a-zA-Z0-9]'

    # Use the -replace operator to remove non-alphanumeric characters
    $result = $InputString -replace $pattern

    # Return the modified string
    return $result
}

Export-ModuleMember -Function Remove-NonAlphaNumericCharacters