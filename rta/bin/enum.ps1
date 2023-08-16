$Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
$DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
$DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
$Members = @($DAgroup.psbase.invoke("Members"))
$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
Write-Host $MemberNames