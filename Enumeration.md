# Enumeration

- [Azure Tenant](#azure-tenant)
- [Email IDs](#email-ids)
- [Azure Services](#azure-services)
- [Login Information](#login-information)
- [Session state](#session-state)
- [Current tenant details](#current-tenant-details)
- [User](#user)
- [Groups](#groups)
- [Roles](#roles)
- [Devices](#devices)
- [Apps](#apps)
- [Service principals](#service-principals)
- [Context](#context)
- [Subscription](#subscription)
- [Ressource](#ressource)
- [RBAC Rolle assignents](#rbac-role-assignments)
- [AAD Users](#aad-users)
- [AAD Groups](#aad-groups)
- [AAD Apps](#aad-apps)
- [AAD Service principals](#aad-service-principals)


## Azure Tenant


Get if Azure tenant is in use, tenant name and Federation

```
https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1
```

Get the Tenant ID

```
https://login.microsoftonline.com/[DOMAIN]/.well-known/openid-configuration
```

Validate Email ID by sending requests to

```
https://login.microsoftonline.com/common/GetCredentialType
```

Using AADInternals :
```
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose
```

Get tenant name, authentication, brand name (usually same as directory name) and domain name
```
Get-AADIntLoginInformation -UserName root@defcorphq.onmicrosoft.com
```

Get tenant ID
```
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com
```

Get tenant domains
```
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com
Get-AADIntTenantDomains -Domain deffin.onmicrosoft.com
Get-AADIntTenantDomains -Domain microsoft.com
```

Get all the information
```
Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com
```

### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

Get details of the current tenant (uses the account extension)
```
az account tenant list
```


## Email IDs 

Using 0365creeper (https://github.com/LMGsec/o365creeper) to check if an email ID belongs to a tenant.
```
C:\Python27\python.exe
C:\AzAD\Tools\o365creeper\o365creeper.py -f
C:\AzAD\Tools\emails.txt -o
C:\AzAD\Tools\validemails.txt
```


## Azure Services 

### using MicroBurst (https://github.com/NetSPI/MicroBurst)
```
Import-Module C:\AzAD\Tools\MicroBurst\MicroBurst.psm1 -Verbose
```

Enumerate all subdomains for an organization specified using the '-Base' parameter:
```
Invoke-EnumerateAzureSubDomains -Base defcorphq -Verbose
```


## Login information


### using AADInternals :
```
Get-AADIntLoginInformation -UserName admin@defcorphq.onmicrosoft.com
```


## Session State

### using MSGraph PowerShell module
```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```

List the current signed-in user
```
Get-MgContext
```

### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

List the current signed-in user
```
az ad signed-in-user show
```


## Current Tenant Details

### using MSGraph PowerShell module
```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)

Get-MgOrganization | fl *
```


## User

### using MSGraph PowerShell module

```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```

Enumerate all users
```
Get-MgUser -All
```

Enumerate a specific user
```
Get-MgUser -UserId test@defcorphq.onmicrosoft.com 
```

Search for a user based on string in first characters of DisplayName or userPrincipalName (wildcard not supported)
```
Get-MgUser -Filter "startsWith(DisplayName, 'a')" -ConsistencyLevel eventual
```

Search for users who contain the word "admin" in their Display name
```
Get-MgUser -All |?{$_.Displayname -match "admin"} 
Get-MgUser -Search '"DisplayName:admin"' -ConsistencyLevel eventual
```

List all the attributes for a user
```
Get-MgUser -UserId test@defcorphq.onmicrosoft.com | fl * 
Get-MgUser -UserId test@defcorphq.onmicrosoft.com | %{$_.PSObject.Properties.Name}
```

Search attributes for all users that contain the string "password":
```
Get-MgUser -All |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ -$($Properties.$_)"}}}
```


All users who are synced from on-prem
```
Get-MgUser -All | ?{$_.OnPremisesSecurityIdentifier -ne $null}
```

All users who are from Entra ID
```
Get-MgUser -All | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

Objects created by any user (use -ObjectId for a specific user)
```
Get-MgUserCreatedObject -UserId test@defcorphq.onmicrosoft.com | fl *
```

Objects owned by a specific user
```
Get-MgUserOwnedObject -UserId test@defcorphq.onmicrosoft.com | fl *
```


### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

List all the users in Entra ID and format output in table
```
az ad user list --output table
```


## Groups

### using MSGraph PowerShell module

```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```


List all Groups
```
Get-MgGroup -All
```

Enumerate a specific group
```
Get-MgGroup -GroupId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

Enumerate a specific group
```
Get-MgGroup -GroupId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

Search for a group based on string in first characters of DisplayName (wildcard not supported)
```
Get-MgGroup -ConsistencyLevel eventual -Search '"DisplayName:A"'
```

To search for groups which contain the word "admin" in their name
```
Get-MgGroup -ConsistencyLevel eventual -Search '"DisplayName:Admin"'
```

Get Groups that allow Dynamic membership
```
Get-MgGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}
```

All groups that are synced from on-prem (note that security groups are not synced)
```
Get-MgGroup -All| ?{$_.OnPremisesSecurityIdentifier -ne $null}
```

All groups that are from Entra ID
```
Get-MgGroup -All | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

Get members of a group
```
Get-MgGroupMember -GroupId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

Get groups and roles where the specified user is a member
```
(Get-MgUserMemberOf -UserId test@defcorphq.onmicrosoft.com ).AdditionalProperties
```


## Roles


### using MSGraph PowerShell module
```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```

Get all available role templates
```
Get-MgDirectoryRoleTemplate
```

Get all enabled roles (a built-in role must be enabled before usage)
```
Get-MgDirectoryRole
```

Enumerate users to whom roles are assigned
```
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id 
(Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId).AdditionalProperties
```

Enumerate custom directory roles
```
Get-MgRoleManagementDirectoryRoleDefinition | ?{$_.IsBuiltIn -eq $False} | select DisplayName
```


## Devices


###using MSGraph PowerShell module
```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```

Get all Azure joined and registered devices
```
Get-MgDevice –All | fl * 
```

List all the active devices (and not the stale devices)
```
Get-MgDevice –All | ?{$_.ApproximateLastSignInDateTime -ne $null}
```

List Registered owners of all the devices
```
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredOwner -DeviceId $i).AdditionalProperties}
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredOwner -DeviceId $i).AdditionalProperties.userPrincipalName}
```

List Registered users of all the devices
```
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredUser -DeviceId $i).AdditionalProperties}
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredUser -DeviceId $i).AdditionalProperties.userPrincipalName}
```

List devices owned by a user
```
(Get-MgUserOwnedDevice -userId michaelmbarron@defcorphq.onmicrosoft.com).AdditionalProperties
```

List devices registered by a user
```
(Get-MgUserRegisteredDevice -userId michaelmbarron@defcorphq.onmicrosoft.com).AdditionalProperties
```

List devices managed using Intune
```
Get-MgDevice -All| ?{$_.IsCompliant -eq "True"} | fl *
```


## Apps


Using MSGraph PowerShell module
```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```

Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app. 
```
Get-MgApplication -All
```

Get all details about an application
```
Get-MgApplicationByAppId -AppId f072c4a6-b440-40de-983fa7f3bd317d8f | fl *
```

Get an application based on the display name
```
Get-MgApplication -All | ?{$_.DisplayName -match "app"} 
```

The Get-MgApplication will show all the applications details including password but  password value is not shown. List all the apps with an application password
```
Get-MgApplication -All| ?{$_.PasswordCredentials -ne $null}
```

Get owner of an application 
```
(Get-MgApplicationOwner -ApplicationId 35589758-714e-43a9-be9e94d22fdd34f6).AdditionalProperties.userPrincipalName
```

Get Apps where a User has a role (exact role is not shown)
```
Get-MgUserAppRoleAssignment -UserId roygcain@defcorphq.onmicrosoft.com | fl * 
```

Get Apps where a Group has a role (exact role is not shown)
```
Get-MgGroupAppRoleAssignment -GroupId 57ada729-a581-4d6f-9f16-3fe0961ada82 | fl *
```


## Service Principals

### using MSGraph PowerShell module
```
Install-Module Microsoft.Graph
Connect-MgGraph
$Token = eyJ0…
Connect-MgGraph –AccessToken ($Token | ConvertToSecureString -AsPlainText -Force)
```

Get all service principals
```
Get-MgServicePrincipal -All
```

Get all details about a service principal
```
Get-MgServicePrincipal -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791 | fl *
```

Get an service principal based on the display name
```
Get-MgServicePrincipal –All | ?{$_.DisplayName -match "app"}
```

List all the service principals with an application password
```
Get-MgServicePrincipal –All | ?{$_.KeyCredentials -ne $null} 
```

Get owner of a service principal
```
(Get-MgServicePrincipalOwner -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791).AdditionalProperties.userPrincipalName
```

Get objects owned by a service principal
```
Get-MgServicePrincipalOwnedObject -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791
```

Get objects created by a service principal
```
Get-MgServicePrincipalCreatedObject -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791
```

Get group and role memberships of a service principal
```
Get-MgServicePrincipalMemberOf -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791 | fl *
```

### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

List only the userPrincipalName and givenName (case sensitive) for all the users in Entra ID and format output in table. Az cli uses JMESPath query
```
az ad user list --query "[].[userPrincipalName,displayName]" --output table
```

List only the userPrincipalName and givenName (case sensitive) for all the users in Entra ID, rename the properties and format output in table
```
az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table
```


## Context

### using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Context(Account, Tenant, Subscription etc.)
```
Get-AzContext
```

List all available contexts
```
Get-AzContext -ListAvailable
```


## Subscription

### using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Enumerate subscriptions accessible by the current user
```
Get-AzSubscription
```


### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

Get details of the current subscription (uses the account extension)
```
az account subscription list
```


## Ressource

Using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Enumerate all resources visible to the current user
```
Get-AzResource
```


## RBAC role assignments

### using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Enumerate all Azure RBAC role assignments
```
Get-AzRoleAssignment
```


## AAD Users

### using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Enumerate all users
```
Get-AzADUser
```

Enumerate a specific user
```
Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com
```

Search for a user based on string in first characters of DisplayName (wildcard not supported)
```
Get-AzADUser -SearchString "admin"
```

Search for users who contain the word "admin" in their Display name
```
Get-AzADUser |?{$_.Displayname -match "admin"}
```

### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

Enumerate all users
```
az ad user list
az ad user list --query "[].[displayName]" -o table
```

Enumerate a specific user (lists all attributes)
```
az ad user show --id test@defcorphq.onmicrosoft.com
```

Search for users who contain the word "admin" in their Display name (case sensitive):
```
az ad user list --query "[?contains(displayName,'admin')].displayName"
```

When using PowerShell, search for users who contain the word "admin" in their Display name. This is NOT case-sensitive:
```
az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```

All users who are synced from on-prem
```
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName" 
```

All users who are from Entra ID
```
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
```


## AAD Groups

### using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

List all groups
```
Get-AzADGroup
```

 Enumerate a specific group
```
Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

 Search for a group based on string in first characters of DisplayName(wildcard not supported)
```
Get-AzADGroup -SearchString "admin" | fl *
```

To search for groups which contain the word "admin" in their name
```
Get-AzADGroup |?{$_.Displayname -match "admin"} 
```

Get members of a group
```
Get-AzADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```


### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

List all Groups
```
az ad group list 
az ad group list --query "[].[displayName]" -o table
```

Enumerate a specific group using display name or object id
```
az ad group show -g "VM Admins" 
az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e 
```

Search for groups that contain the word "admin" in their Display name (case sensitive) - run from cmd:
```
az ad group list --query "[?contains(displayName,'admin')].displayName"
```

When using PowerShell, search for groups that contain the word "admin" in their Display name. This is NOT case-sensitive:
```
az ad group list | ConvertFrom-Json | %{$_.displayName -match "admin"} 
```

All groups that are synced from on-prem
```
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName" 
```

All groups that are from Entra ID
```
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
```

Get members of a group
```
az ad group member list -g "VM Admins" --query "[].[displayName]" -o table 
```

Check if a user is member of the specified group
```
az ad group member check --group "VM Admins" --member-id b71d21f6-8e09-4a9d-932a-cb73df519787
```

Get the object IDs of the groups of which the specified group is a member
```
az ad group get-member-groups -g "VM Admins" 
```


## AAD Apps

Using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app.
```
Get-AzADApplication
```

Get all details about an application
```
Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0
```

Get an application based on the display name
```	
Get-AzADApplication | ?{$_.DisplayName -match "app"} 
```

The Get-AzADAppCredential will show the applications with an application password but password value is not shown. List all the apps with an application password
```
Get-AzADApplication | %{if(Get-AzADAppCredential -ObjectID $_.ID){$_}}
```


### using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app. 
```
az ad app list
az ad app list --query "[].[displayName]" -o table
```

Get all details about an application using identifier uri, application id or object id
```
az ad app show --id a1333e88-1278-41bf-8145-155a069ebed0
```

Get an application based on the display name (Run from cmd)
```
az ad app list --query "[?contains(displayName,'app')].displayName"
```

When using PowerShell, search for apps that contain the word "slack" in their Display name. This is NOT case-sensitive:
```
az ad app list | ConvertFrom-Json | %{$_.displayName -match "app"} 
```

Get owner of an application 
```
az ad app owner list --id a1333e88-1278-41bf-8145-155a069ebed0 --query "[].[displayName]" -o table 
```

List apps that have password credentials
```
az ad app list --query "[?passwordCredentials != null].displayName" 
```

List apps that have key credentials (use of certificate authentication)
```
az ad app list --query "[?keyCredentials != null].displayName"
```


## AAD Service Principals

Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service account'!

Using Az PowerShell
```
Connect-AzAccount 
	
#Alternative
$creds = Get-Credential
Connect-AzAccount -Credential $creds

#Alternative
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```

Get all service principals
```
Get-AzADServicePrincipal
```

Get all details about a service principal
```
Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264
```

Get a service principal based on the display name
```
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"}
```


### Using Azure CLI

```
az login #open login page using default browser
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 #Using credentials from command line
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 --allow-no-subscriptions #If the user has no permission on subscription
```

Get all service principals
```
az ad sp list --all
az ad sp list --all --query "[].[displayName]" -o table
```

Get all details about a service principal using service principal id or object id
```
az ad sp show --id cdddd16e-2611-4442-8f45-053e7c37a264
```

Get a service principal based on the display name
```
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
```

When using PowerShell, search for service principals that contain the word "slack" in their Display name. This is NOT case-sensitive:
```
az ad sp list --all | ConvertFrom-Json | %{$_.displayName -match "app"}
```

Get owner of a service principal
```
az ad sp owner list --id cdddd16e-2611-4442-8f45-053e7c37a264 --query "[].[displayName]" -o table 
```

Get service principals owned by the current user
```
az ad sp list --show-mine
```

List apps that have password credentials
```
az ad sp list --all --query "[?passwordCredentials != null].displayName" 
```

List apps that have key credentials (use of certificate authentication)
```
az ad sp list -all --query "[?keyCredentials != null].displayName"
```


- [Back to the top](#enumeration)