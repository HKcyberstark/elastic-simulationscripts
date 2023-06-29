function Invoke-TestWMI {
    $FilterArgs = @{name='WMITestFilter';EventNameSpace='root\CimV2';QueryLanguage="WQL";Query="SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"};
    $Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs
    $ConsumerArgs = @{name='WMITestConsumer';CommandLineTemplate="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe copy C:\Windows\System32\cmd.exe C:\a.exe";}
    $Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs
    $FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{Filter = [Ref] $Filter;Consumer = [Ref] $Consumer;}
    notepad.exe
    Start-Sleep -s 5

    Get-WmiObject -Namespace root\Subscription -Class __EventConsumer | Where-Object { $_.Name -eq "WMITestConsumer" } | ForEach-Object { Remove-WmiObject -InputObject $_ }
    Get-WmiObject -Namespace root\Subscription -Class __EventFilter | Where-Object { $_.Name -eq "WMITestFilter" } | ForEach-Object { Remove-WmiObject -InputObject $_ }
    Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Where-Object { $_.Consumer -eq '\\.\ROOT\subscription:CommandLineEventConsumer.Name="WMITestConsumer"' } | ForEach-Object { Remove-WmiObject -InputObject $_ }
}
Invoke-TestWMI