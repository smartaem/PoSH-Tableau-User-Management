
#required active directory module
Import-Module activedirectory
#import ldap funtion module
$parentpath = Split-Path -parent $PSCommandPath
$sdspmodule = $parentpath + "\DirectoryServiceProtocol\S.DS.P.psm1"
Import-Module $sdspmodule

function Get-LDAPHash([array]$array,$object)
{
    $hash = @{}
    $array | foreach { $hash[$_.Samaccountname] = "$($_.samaccountname):$($_.displayname):$($_.mail)"}
    return $hash[$object]
}

function Get-LDAPUsernameEmail($Groupdata,$Username)
{
    
    (Get-LDAPHash -array $Groupdata -object $Username).split(':')[2]
}
function Get-LDAPUsernameDisplaynameHash([array]$ObjArray,$Samaccountname)
{
    $hash = @{}
    $ObjArray | foreach { $hash[$_.Samaccountname] = "$($_.displayname)"}
    return $hash[$Samaccountname]
}

function Get-LDAPGroupMembers()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $Server, 
        [ValidateNotNullOrEmpty()]
        [String] $Port,       
        [ValidateNotNullOrEmpty()]
        [String] $Username,
        [ValidateNotNullOrEmpty()]
        [String]$Password,
        [CmdletBinding()]
        [ValidateNotNullOrEmpty()]
        [String] $Domain,        
        [ValidateNotNullOrEmpty()]
        [String]$LDAPGroupName ,
        [ValidateNotNullOrEmpty()]
        [String]$SearchBase
    )
    $cred=new-object System.Net.NetworkCredential("$Username","$Password","$Domain")
    
    Write-Verbose "LDAP: Connecting to LDAP server $server, with username $username"
    Write-Verbose "Domain: $domain"
    Write-Verbose "Search base: $searchbase"
    Write-Verbose "LDAP group name: $LDAPGroupName "

    $GroupDN = Find-LdapObject -Port "$Port"  -SearchFilter:"(&(objectClass=group)(cn=$LDAPGroupName*))" `
    -SearchBase:"$SearchBase" -Credential:$cred -ldapserver:$Server
    $DN = $GroupDN.distinguishedName
    Find-LdapObject  -SearchFilter:"(&(objectCategory=person)(MemberOf=$DN))" `
    -SearchBase:"$SearchBase" -PropertiesToLoad "mail","samaccountname","displayName"  -Credential:$cred -ldapserver:$server
 }

function Get-LDAPGroupMemberByUserName($SamAccountName, [array]$GroupData)
{
    return Get-LDAPHash -array $GroupData -object $SamAccountName

}
function Get-LDAPGroupMemberByEmail($SamAccountName, [array]$GroupData)
{
    return Get-LDAPHash -array $GroupData -object $SamAccountName

}

function Get-LDAPGroupMemberListBySamaccountName([array]$GroupData)
{
    return $GroupData | select samaccountname,displayname,mail

}
