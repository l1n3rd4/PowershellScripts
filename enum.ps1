systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"

wmic logicaldisk get caption

fsutil fsinfo drives 

set

# (installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading)
#IF exist C:\Windows\CCM\SCClient.exe ECHO.SCCM is installed 

tasklist /SVC

wmic process list full

wmic startup get caption,command

autorunsc

net share

netstat -ano

netsh firewall show state
netsh firewall show config

arp -A
type C:\WINDOWS\System32\drivers\etc\hosts

ipconfig /displaydns 

netsh wlan show profiles

quser || query user
net user %username%
net user %USERNAME% /domain 2>nul
whoami /all

net localgroup
klist

accesschk.exe -uwcqv "Authenticated Users" *
#sc query 

#fsutil 
#HKLM \ Software \ Microsoft \ Windows NT \ CurrentVersion \ ProfileLis

START /B program > somefile.txt

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SentinelStaticEngine
start /b .\frminst.exe /forceuninstall > c:\out.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4
