################################ Register Function ################################
Function zImport-PSModule{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ModuleName,
        [Parameter(Mandatory=$false)][bool]$Permissif=$false
    )

    if(Get-Module -ListAvailable -Name $ModuleName){
        Import-Module $ModuleName
        $res=$true
    }else{
        Write-error "Module Powershell Missing: $ModuleName"
        $res=$false
        if($Permissif -eq $false){Break}
    }

    return $res
}


Function zGet-ADuserEnabledExpired{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][string]$ADSearchbase
    )

    #Module Management
    zImport-PSModule -ModuleName ActiveDirectory | out-null

    #Init var
    $lstUserEnabledExpired=@()
    $dateNow=Get-date

    #Param ADSearchbase management
    if([string]::IsNullOrEmpty($ADSearchbase)){
        $lstUsersEnabled=Get-ADUser -Filter "Enabled -eq 'true'" -Properties AccountExpirationDate
    }else{
        $lstUsersEnabled=Get-ADUser -Filter "Enabled -eq 'true'" -Searchbase $ADSearchbase -Properties AccountExpirationDate
    }

    #Collect user enabled with expiration out of date
    foreach($UsersEnabled in $lstUsersEnabled){
        if($UsersEnabled.AccountExpirationDate -lt $dateNow -and ![string]::IsNullOrEmpty($UsersEnabled.AccountExpirationDate)){
            $lstUserEnabledExpired+=$UsersEnabled
        }
    }


    return $lstUserEnabledExpired
}


################################ Module Management ################################
zImport-PSModule -ModuleName ActiveDirectory | out-null


################################ Main ################################
### Inint Var ###
$LogFile= "c:\temp\DisableExpiredUsers_$(get-date -Format "yyyyMMddHHmmss").csv"
$lstUserEnabledExpired=""
$Res=@()

### Main ###

$lstUserEnabledExpired=zGet-ADuserEnabledExpired -ADSearchbase "DC=teddycorp,DC=lab"


foreach($userEnabledExpired in $lstUserEnabledExpired){

    $DataCollect = New-Object System.object
    $DataCollect | Add-Member -name ‘UserPrincipalName’ -MemberType NoteProperty -Value $userEnabledExpired.UserPrincipalName
    $DataCollect | Add-Member -name ‘DistinguishedName’ -MemberType NoteProperty -Value $userEnabledExpired.DistinguishedName
    $DataCollect | Add-Member -name ‘SamAccountName’ -MemberType NoteProperty -Value $userEnabledExpired.SamAccountName
    $DataCollect | Add-Member -name ‘OrigineStatusEnabled’ -MemberType NoteProperty -Value $userEnabledExpired.Enabled
    
    #Disable-ADAccount -Identity $userEnabledExpired.DistinguishedName

    $DataCollect | Add-Member -name ‘NewStatusEnabled’ -MemberType NoteProperty -Value $(Get-ADUser -Identity $userEnabledExpired.DistinguishedName).Enabled
    
    $Res+=$DataCollect
}

$Res | Export-Csv $LogFile -Encoding UTF8 -Delimiter ";"
