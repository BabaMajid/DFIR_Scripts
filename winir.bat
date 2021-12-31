@ECHO OFF

REM This scripts collects basic artifacts from a windows OS and saves them in text file seperately.

set host=%COMPUTERNAME%

REM Creates directory by hostname in current working directory.

mkdir %cd%\evidence-%host%

REM Lists all local users and save in users.txt file.

powershell "Get-LocalUser | select *" > %cd%\evidence-%host%\users.txt

echo  Members in Administrator Group >> %cd%\evidence-%host%\groups.txt
echo:
net localgroup administrators > %cd%\evidence-%host%\groups.txt

echo Members in Remote Desktop Users Group >> %cd%\evidence-%host%\groups.txt
echo:
net localgroup "Remote Desktop Users" >> %cd%\evidence-%host%\groups.txt

echo  Members in Remote Management Users Group>> %cd%\evidence-%host%\groups.txt
echo:
net localgroup "Remote Management Users" >> %cd%\evidence-%host%\groups.txt

echo  Members in Power Users Group >> %cd%\evidence-%host%\groups.txt
echo:
net localgroup "Power Users"  >> %cd%\evidence-%host%\groups.txt

REM List all processes with name,path,pid,ppid,commandlinbe. FC tell powershell to custom format the output.

powershell " Get-WmiObject win32_Process | select-object name,executablepath,processid,parentprocessid,commandline|FC"  >  %cd%\evidence-%host%\processes.txt

REM List all installed applications

powershell "get-wmiobject -class win32_product | select Name,Vendor,Version"  > %cd%\evidence-%host%\installed_apps.txt

REM List all the Running Services with name, startmode,pathname. It will only list running services.

powershell "get-wmiobject -class win32_service | Where-Object { $_.State -like  'Running'} | select name,startmode,pathname" >  %cd%\evidence-%host%\services.txt

REM List all running scheduled tasks. Note it will only list scheduled tasks created through schtasks/task scheduler. Tasks created by at command nd scheduled jobs will not be listed.

powershell "Get-ScheduledTask | where-object {$_.State -eq 'Ready'} | select TaskName,TaskPath" > %cd%\evidence-%host%\scheduled-tasks.txt

REM List autostart programs(winlogon entries, boot execute,logon startup and autostart services) using sysinternals autorunsc.exe 

%cd%\Tools\Autorunsc.exe -accepteula  wlb -o %cd%\evidence-%host%\autostart.txt

REM List Firewall state for all profiles and export current firewall configurations. But his is hardly used during investigation.

netsh advfirewall show allprofiles > %cd%\evidence-%host%\firewall-state.txt && netsh advfirewall export %cd%\evidence-%host%\firewall-config.wfw

REM List Network Connections along with executables

netstat -nfqb > %cd%\evidence-%host%\netstat.txt

REM Copy all prefetch files to a newly created prefetch folder in our evidence directory. Prefetching is disabled on windows OS by default.

mkdir %cd%\evidence-%host%\prefetch
copy C:\windows\prefetch\*.pf %cd%\evidence-%host%\prefetch

REM Copy event logs only security.

mkdir %cd%\evidence-%host%\Logs
copy c:\windows\system32\winevt\logs\* %cd%\evidence-%host%\Logs\










































