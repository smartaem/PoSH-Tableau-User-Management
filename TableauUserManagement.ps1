[CmdletBinding(SupportsShouldProcess=$true)]
Param()

$Global:tableausessiontoken = [string]::Empty
$Global:config = [array]::Empty

#import LDAP functions
$parentpath = Split-Path -parent $PSCommandPath
$ldpapath = $parentpath + "\LDAP\LDAP.PS1"
.$ldpapath


#Get Config
try
{
    $Global:config =  Get-Content "$(Split-Path -parent $PSCommandPath)\config\groupmapping.config" | ConvertFrom-Json -ErrorAction stop
    
}
catch [System.Exception]{
    Write-Error "`n[[Unable to load config file. Please validate that the configuration file is accurate and and valid JSON file. This script will now exit]]`n`n"
    write-error $_.Exception.ToString()
    exit

}

#$Global:config
$TableauBaseURL = $config.tableau.url

# Sent output to console and file
$logfile = $parentpath + "\log\TableauUsermanagement.log"
function Write-log
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$True,Position=1)]
        [String]$MessageToWrite,        
        [ValidateNotNullOrEmpty()]
        [String]$filepath = $logfile
    )

    Write-Verbose -Message $MessageToWrite
    $MessageToWrite | Out-File -FilePath $filepath -Append


}


#retreive the object ID from returned result
function Get-TableauObjectID([array]$array,$object)
{
    $hash = @{}
    $array | foreach { $hash[$_.Name] = $_.id }
    return $hash[$object]
}


#Connect to tableau server
function Connect-TableauServer()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$Server,        
        [ValidateNotNullOrEmpty()]
        [String]$Username,
        [ValidateNotNullOrEmpty()]
        [String]$Password
    )
    
    $authxml= @"
    <tsRequest><credentials name="$Username" password="$Password"><site contentUrl="" /> </credentials></tsRequest>
"@

    $uri = $Server + "/api/2.0/auth/signin"
    try
    {
        [xml]$xmlouput = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/xml" -Body $authxml
        $Global:tableausessiontoken = $xmlouput.tsResponse.credentials.token

    }
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception: $eexceptionmessage during execution of Connect-TableauServer for URI: $uri. Exiting..."
        Exit
    }
}

# Sign out of Tableau session
function Close-TableauSession
{
[CmdletBinding()]

    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
    $uri = $TableauBaseURL +  "/api/2.0/auth/signout"
    $response = [string]::Empty
    try
    {
        $response = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/xml" -Headers $headers
        
       #$uri
        if ($response -eq "")
            {
                write-verbose "Successfully signed out"
            }
            else
            {
                write-verbose "Signout failed. Error:  + $response]"
            }
    }
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        write-verbose "Signout failed."
        Write-Error "Caught an exception during Close-TableauSession: $exceptionmessage : $uri"

    }
}

# Retrieve tableau site ID by the site name
function Get-TableauSiteIDByName() 
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$sitename
    )
    $uri = $TableauBaseURL + "/api/2.0/sites/$($sitename)?key=name"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    try
    {
        [xml]$response = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        [string]$siteid = ($response.tsResponse.site.id).tostring()
        [string]$rsitename = ($response.tsResponse.site.name).tostring()
        if($sitename -contains $rsitename){return $siteid}
        else{Write-warning "No Site was found with the name: $sitename"}
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauSiteIDByName(): $exceptionmessage  URI: $uri "

    }
}

function Get-TableauGroups()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$siteid  
    )
    $siteid = Get-TableauSiteIDByName -sitename $siteid
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/groups/"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        return $request.tsResponse.groups.group
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauGroups(): $exceptionmessage :::: URI $uri "
    }
}

# Gets the the Group ID of Tableau group by its name
function Get-TableauGroupIDbyName()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$siteid,        
        [ValidateNotNullOrEmpty()]
        [String] $groupname
    )

    $siteid = Get-TableauSiteIDByName -sitename $siteid
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/groups/"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        $groups = $request.tsResponse.groups.group
        return (Get-TableauObjectiD -array $groups -object $groupname)

    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauGroupIDbyName(): $exceptionmessage :::: URI: $uri "
    }
}


function Get-TableauUsersInGroup()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$sitename ,        
        [ValidateNotNullOrEmpty()]
        [String] $groupname
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $groupid = Get-TableauGroupIDbyName -siteid $sitename -groupname $groupname
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/groups/$groupid/users"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        $users = $request.tsResponse.users.user
        return $users | select name

    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauUsersInGroup(): $exceptionmessage : :::: URI: $uri "
    }
}

function Set-TableauGroupDefaultRole()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$siteid ,        
        [ValidateNotNullOrEmpty()]
        [String]$groupname ,
        [ValidateNotNullOrEmpty()]
        [String]$role
    )
    $siteid = Get-TableauSiteIDByName -sitename $siteid
    $groupid = 
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/groups/$groupid"
    
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    $requestxml = @"
    <tsRequest>
      <user name="$userid"
        siteRole="$role" 
        email="$email" />
    </tsRequest>
"@
    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        return $request.tsResponse.groups.group
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauGroups(): $exceptionmessage :::: URI: $uri "
    }
}

function Add-UserToTableauSite()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $sitename,        
        [ValidateNotNullOrEmpty()]
        [String] $userid,
        [ValidateNotNullOrEmpty()]
        [String]$role,
        [string]$email
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/users"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    $requestxml = @"
    <tsRequest>
      <user name="$userid"
        siteRole="$role" 
        email="$email" />
    </tsRequest>
"@


    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/xml" -Headers $headers -Body $requestxml
        
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Add-UserToTableauSite(): $exceptionmessage :::: URI: $uri "
    }
}

#Update tableau user with more  information - full username, email, etc
function Update-TableauUser()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $sitename,        
        [ValidateNotNullOrEmpty()]
        [String] $username,
        [ValidateNotNullOrEmpty()]
        [String]$fullname,
        [String]$emailaddress,
        [String]$authSetting = 'SAML'
        
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $userid = Get-TableauUserIDbyName -sitename $sitename -username $username

    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/users/$userid"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    $requestxml = @"
    <tsRequest>
        <user fullName="$fullname"
        email="$emailaddress"
        authSetting="$authSetting" />
    </tsRequest>
"@


    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/xml" -Headers $headers -Body $requestxml
        
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Update-TableauUser(): $exceptionmessage :::: URI: $uri "
    }
}

function Get-TableauUsersBySite()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$sitename
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/users"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
    
    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        return $request.tsResponse.users.user
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauUsersBySite(): $exceptionmessage :::: URI: $uri "
    }

}
function Get-TableauUserIDbyName()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $sitename,        
        [ValidateNotNullOrEmpty()]
        [String] $username
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $uri = $TableauBaseURL + "/api/2.0/sites/$($siteid)/users"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
    
    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/xml" -Headers $headers
        $users = $request.tsResponse.users.user
        return (Get-TableauObjectiD -array $users -object $username)
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running Get-TableauUserIDbyName(): $exceptionmessage :::: URI: $uri "
    }
}

function Get-TableauValidateUSer()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $sitename,        
        [ValidateNotNullOrEmpty()]
        [String] $username
    )
   
    if(Get-TableauUserIDbyName -sitename $sitename -username $username){return $true}
    else{return $false}   
}



function Set-TableauUserGroup()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String]$sitename ,        
        [ValidateNotNullOrEmpty()]
        [String] $username,
        [ValidateNotNullOrEmpty()]
        [String]$groupname
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $groupid = Get-TableauGroupIDbyName -siteid $sitename -groupname $groupname
    $userid = Get-TableauUserIDbyName -sitename $sitename -username $username
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/groups/$groupid/users"
    $headers = @{}
    
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
    $xmlrequest = @"
    <tsRequest>
    <user id="$userid" />
    </tsRequest>
"@
    try
    {
        #see if user is already in group
        $usersingroup = Get-TableauUsersInGroup -sitename $sitename -groupname $groupname
        if(($usersingroup -icontains $username))
        {
            Write-Verbose "TABLEAU: The specified user is already in the group"
            
        }
        else{[xml]$request = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/xml" -Headers $headers -Body $xmlrequest}
        
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
       # Write-Error "Caught an exception Set-TableauUserGroup(): $exceptionmessage :::: URL: $uri "
    }

}

function Remove-TableauUserFromGroup()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $sitename,        
        [ValidateNotNullOrEmpty()]
        [String] $username,
        [ValidateNotNullOrEmpty()]
        [String]$groupname
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $groupid = Get-TableauGroupIDbyName -siteid $sitename -groupname $groupname
    $userid = Get-TableauUserIDbyName -sitename $sitename -username $username
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/groups/$groupid/users/$userid"
    $headers = @{}
    
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
   
    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method DEL -ContentType "application/xml" -Headers $headers
        #wite-Host $request
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception running  Remove-TableauUserFromGroup): $exceptionmessage :::: URL: $uri "
    }

}
function Remove-TableauUserFromSite()
{
[CmdletBinding()]
    Param
    (        
        [ValidateNotNullOrEmpty()]
        [String] $sitename,        
        [ValidateNotNullOrEmpty()]
        [String] $username
    )
    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $userid = Get-TableauUserIDbyName -sitename $sitename -username $username
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/users/$userid"
    $headers = @{}
    
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
   
    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method DEL -ContentType "application/xml" -Headers $headers
        #Write-Host $request
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception Remove-TableauUserFromSite(): $exceptionmessage :::: URL: $uri "
    }

}


function Get-TableauUserLDAPCompare()
{
[CmdletBinding()]
    Param
    (   
        [String] $TableauUser,
        [array] $LDAPUsers,
        [switch]$isEmpty
    )

    if($LDAPUsers -icontains $TableauUser){return $true}
    elseif($isEmpty){ if($LDAPUsers.Count -eq 0 ){return $true}}
    else{return $false}
}
function Get-LDAPUserTableauCompare()
{
[CmdletBinding()]
    Param
    (        
        [String]$LDAPUser ,
        [Array]$TableauUsers ,
        [switch]$isEmpty
    )
    if($TableauUsers -icontains $LDAPUser){return $true}
    elseif($isEmpty)
    {if($TableauUsers.Count -eq 0 ){return $true}}
    else{return $false}
}


################################
# WORKBOOK FUNTIONS
function Get-AllProjectsInSite()
{
[CmdletBinding()]
    Param
    (        
        [String]$SiteName 
    )

    # GET /api/api-version/sites/site-id/projects
    $siteid = Get-TableauSiteIDByName -sitename $SiteName
    $uri = $TableauBaseURL + "/api/2.0/sites/$siteid/projects"
    $headers = @{}
    
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken
    
    try
    {
        [xml]$request = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/xml" -Headers $headers -Body $xmlrequest
        return $request
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception Get-AllProjectsInSite(): $exceptionmessage :::: URL: $uri "
    }



}

#Get projects owned by a user
function Get-WorkBookOwnerByUser()
{
[CmdletBinding()]
    Param
    (   
        [ValidateNotNullOrEmpty()]     
        [String]$Sitename,
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )

    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $userid = Get-TableauUserIDbyName -sitename $sitename -username $Username
    $uri = $TableauBaseURL + "/api/2.0/sites/$($siteid)/users/$userid/workbooks?ownedBy=true"
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    try
    {
        $request = Invoke-RestMethod -Uri $uri -Method GET -ContentType "application/xml" -Headers $headers
        return $request.tsResponse.workbooks.workbook
    }
    
    catch [System.Exception]
    {
        $exceptionmessage = $_.Exception.ToString()
        Write-Error "Caught an exception Get-WorkBookOwnerByUser(): $exceptionmessage :::: URL: $uri "
    }

}


#Set workbook owner
 function Set-WorkBookOwner()
{
[CmdletBinding()]
    Param
    (   
        [ValidateNotNullOrEmpty()]     
        [String]$Sitename,
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        [ValidateNotNullOrEmpty()]
        [string]$TransferUser
    )

    $siteid = Get-TableauSiteIDByName -sitename $sitename
    $userid = Get-TableauUserIDbyName -sitename $sitename -username $Username
    $TransferUserID = $userid = Get-TableauUserIDbyName -sitename $sitename -username $TransferUser
    
    $headers = @{}
    $headers["X-Tableau-Auth"] = $Global:tableausessiontoken

    $workbooks = Get-WorkBookOwnerByUser -Sitename $sitename -Username $username
    foreach($workbook in $workbooks)
    {
        $workbookID = $workbook.id
        $workbookprojectID = $workbook.project.id
        $xmlrequest = @" 
        <tsRequest>
            <workbook showTabs="show-tabs-flag" >
                <project id="$workbookprojectID" />
                <owner id="$TransferUserID" />
            </workbook>
        </tsRequest>
"@

        $uri = $TableauBaseURL + "/api/2.5/sites/$siteid/workbooks/$workbookID"
   
        try
        {
            Write-Verbose "Transferring workbook [$($workbook.name)] ownership to [$TransferUser]"
            $request = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/xml" -Headers $headers -Body $xmlrequest
            
        }
    
        catch [System.Exception]
        {
            $exceptionmessage = $_.Exception.ToString()
            Write-Error "Caught an exception Set-WorkBookOwner(): $exceptionmessage :::: URL: $uri "
        }
    }

}

# END WORKBOOK FUNCTIONS
################################


#Set-WorkBookOwner -Sitename 'Default' -Username 'admin

#Connect-TableauServer -Server '10.10.16.135' -Username 'admin' -Password ''
#Get-AllProjectsInSite -SiteName 'Default'
#$wgs = Get-WorkBookOwnerByUser -Sitename 'Default' -Username 'smart'
# Get-WorkBookOwnerByUser -Sitename 'Default' -Username 'smart' | ft

################################

# MAIN FUNCTION
Function Main()
{
    #Login into Tableau    
    Connect-TableauServer -Server $($Global:config.tableau.url) -Username $($Global:config.tableau.username) `
     -Password $($Global:config.tableau.password)
    ##LDAP

    #### SET VARIABLES FROM CONFIG FILE
    $ldapsearchbase = $Global:config.ad.searchbase
    $ldapport = $config.ldap.port
    $ldapgroupnames = $config.sites.group_mapping
    $ldapserver = $config.ldap.host  
    $ldapauthusername = $config.ldap.username  
    $ldapauthpassword = $config.ldap.password   
    $ldapdomain =$config.ad.domain
    $tableausite = $config.sites.name

    #####################################

    foreach($ldapgroupname in $ldapgroupnames){
        Write-Verbose "Working on LDAP GROUP: $($ldapgroupname.ldap)"
        # Pull the group members of the ldap group
        $groupmembers = Get-LDAPGroupMembers -Server $ldapserver -port $ldapport -Username $ldapauthusername -Password $ldapauthpassword -Domain $ldapdomain -SearchBase $ldapsearchbase -LDAPGroupName $($ldapgroupname.ldap) 
        
        # Extract the samaccount names found in the ldap group. This will be used to create accounts in TAbleau
        [array]$ldapsamaccountnames=Get-LDAPGroupMemberListBySamaccountName -GroupData $groupmembers
        
        #tableau
        $tgroup = $ldapgroupname.tableau
        $tTableauGroup = Get-TableauUsersInGroup -sitename $tableausite -groupname $tgroup
        
        Write-verbose "====================BEGIN USER DELETION PROCESS========================"
        foreach($tUser in $tTableauGroup)
        {
            write-verbose "======== PROCESSING USER: [$($tuser.name)] =========="
            # see if the user users in ldap are found in Tableau
            if((Get-TableauUserLDAPCompare -LDAPUsers $ldapsamaccountnames.samaccountname -TableauUser $($tUser.name) ))
            {
                Write-Verbose "User [$($tUser.name)] found in LDAP group [$($ldapgroupname.ldap)]"
            }
            else
            {
                #Remove user from from Tableau group and Tableau
                # Check to see if user owns any work books
                if((Get-WorkBookOwnerByUser -Sitename $tableausite -Username $($tuser.name)) -eq $null )
                {
                    Write-verbose "NO WORKBOOK OWNERSHIP" 
                    Write-verbose "User [$($tUser.name)] not found in LDAP group [$($ldapgroupname.ldap)]"
                    Write-verbose "Removing user from Tableau group [$($ldapgroupname.tableau)]"
                    Remove-TableauUserFromGroup -sitename $tableausite -username $($tuser.name) -groupname $ldapgroupname.tableau
                    Write-verbose "Deleting user from Tableau site: [$tableausite]"
                    Remove-TableauUserFromSite -sitename $tableausite -username $($tuser.name)
                }
                else  #The User owns some assets that needs to be reassigned
                {
                    Write-verbose "User [$($tUser.name)] own assets in the tableau site [$tableausite] that will be reassigned to [$($ldapgroupname.defaultuser)] "
                    Write-warning "User [$($tUser.name)] not found in LDAP group [$($ldapgroupname.ldap)]"
                    Write-verbose "Removing user [$($tUser.name)] from Tableau group [$($ldapgroupname.tableau)]"
                    Remove-TableauUserFromGroup -sitename $tableausite -username $($tuser.name) -groupname $ldapgroupname.tableau
                    Write-verbose "Deleting user from Tableau site: [$tableausite]"
                    #User cannot be removed if they are owners on a assets. Change asset ownership. 
                    Set-WorkBookOwner -Sitename $tableausite -Username $($tuser.name)  -TransferUser $($ldapgroupname.defaultuser)
                    #Delete User
                    Remove-TableauUserFromSite -sitename $tableausite -username $($tuser.name)
                }
            }
            write-verbose "======== END PROCESSING USER: [$($tuser.name)] =========="
            
        }
        write-verbose "====================END USER DELETION PROCESS========================"

        write-verbose "`n`n====================BEGIN USER CREATION PROCESS========================"

        $samaccountnames = Get-LDAPGroupMemberListBySamaccountName -GroupData $groupmembers      

        
        
        foreach($samaccountname in $samaccountnames){
            write-verbose "PROCESSING USER: [$($samaccountname.displayname)]"  #*****

           # See if user in LDAP group are not present in Tableau group. Create it and add to appropriate group
            if(!(Get-LDAPUserTableauCompare -LDAPUser $samaccountname.samaccountname -TableauUsers $tTableauGroup.name -isEmpty))
            {
                
                Write-verbose "1.LDAP User [$($samaccountname.samaccountname)] NOT found in Tableau group [$($ldapgroupname.tableau)]"
                # Add the user to group if it is not there.
                Add-UserToTableauSite -sitename $tableausite -userid $($samaccountname.samaccountname) -role $ldapgroupname.rolemapping  -email $(Get-LDAPUsernameEmail -Groupdata $groupmembers -Username $samaccountname.samaccountname) 
                #update newly added user with proper information
                Update-TableauUser -sitename $tableausite -username $($samaccountname.samaccountname) -fullname $($samaccountname.displayname) -emailaddress $($samaccountname.mail)

                if(!(Get-LDAPUserTableauCompare -LDAPUser $samaccountname.samaccountname -TableauUsers $tTableauGroup.name -isEmpty))
                    {Set-TableauUserGroup -sitename  $tableausite -username $($samaccountname.samaccountname) -groupname $($ldapgroupname.tableau)}

            }
            else
            {
                Write-warning "2.LDAP user [$($samaccountname.samaccountname)] not found in Tableau group [$($ldapgroupname.tableau)]"
                Write-Verbose "Creating user [$($samaccountname.samaccountname)] from LDAP group [$($ldapgroupname.ldap)]"
                if(Get-TableauValidateUSer -sitename $tableausite -username $samaccountname.samaccountname)
                {
                    
                    Write-warning "User [$($samaccountname.samaccountname)] already exists"
                    Set-TableauUserGroup -sitename  $tableausite -username $($samaccountname.samaccountname) -groupname $($ldapgroupname.tableau)
                }
                else
                {
                    
                    Add-UserToTableauSite -sitename $tableausite -userid $($samaccountname.samaccountname) -role $ldapgroupname.rolemapping  -email 'smart@liaison.com' # $(Get-LDAPUsernameEmail -Groupdata $groupmembers -Username $samaccountname.samaccountname) 
                    #update newly added user with proper information
                    Update-TableauUser -sitename $tableausite -username $($samaccountname.samaccountname) -fullname $($samaccountname.displayname) -emailaddress $($samaccountname.mail)

                    Set-TableauUserGroup -sitename  $tableausite -username $($samaccountname.samaccountname) -groupname $($ldapgroupname.tableau)
                      
                }
            }

            
        }
        Write-log "`n`n====================END USER CREATION PROCESS========================"

    }
}


function run()
{
    Main
    Close-TableauSession
}


run