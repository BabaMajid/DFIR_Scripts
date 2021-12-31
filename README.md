# DFIR_Scripts
I have encountered few cases where I had to gather basic info from a machine like list of users, network connection, group membership etc. Everytime I either had to goto my EDR or need access to system. To cover this I have created a simple windows script that will do the task and save output in txt format.Currently it only supports windows but I will be adding Linux script too once finished with this windows.T  

winIR.bat can gather below details from a system. To do this you will need admin and powershell access on machine.

i) User Account
ii) Group membership  (only for Administrator, Remote Desktop Users, Remote management users, Power Users).
iii) List of Processes
iv)Installed Applications
v) Running Service 
vi) Schedule Tasks
vii) Auto Start Programs -- For this you need to have sysinternals autorunsc.exe in tools folder in the same location where this script resides.
viii) Copy all prefetch files and saves into a folder.

