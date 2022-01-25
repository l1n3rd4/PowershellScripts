Install-Module ExchangePowerShell 

function Connect-office365{
    $credential = Get-Credential
    $urlOutlook = "https://ps.outlook.com/powershell"

    $Session = New-PSSession `
            -ConfigurationName Microsoft.Exchange `
            -ConnectionUri  $urlOutlook `
            -Credential $credential `
            -Authentication Basic `
            -AllowRedirection

    Import-module msonline
    Connect-MsolService -Credential $credential
}

Connect-office365

Get-UnifiedGroup -Identity "direcional.sp@direcional.com.br" | Get-UnifiedGroupLinks -LinkType Member

Get-Msol

winrm get winrm/config/client/auth
winrm set winrm/config/client/auth @{Basic="true"}


function Get-TargetResource ($Path) {
    # TODO: Add parameters here
    # Make sure to use the same parameters for
    # Get-TargetResource, Set-TargetResource, and Test-TargetResource

    Import-Csv -Path $Path | ForEach-Object {
        New-Msoluser -UserPrincipalName $_.UserPrincipalName `
                     -FirstName $_.FirstName `
                     -LastName $_.LastName `
                     -Department $_.Department `
                     -Title $_.Title `
                     -Office $_.Office `
                     -PhoneNumber $_.PhoneNumber `
                     -Fax $_.Fax `
                     -StreetAddress $_.StreetAddress `
                     -MobilePhone $_.MobilePhone `
                     -City $_.City `
                     -State $_.State `
                     -Country $_.Country `
                     -DisplayName $_.DisplayName `
                     -PostalCode $_.PostalCode `
                     -UsageLocation ""
    }
}