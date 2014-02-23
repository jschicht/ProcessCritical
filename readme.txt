System critical processes

A process can be set as critical, which means that if the process exits, then system will stop imediately. The system will thus BSOD. Getting and setting this information is done through NtQueryInformationProcess and NtSetInformationProcess, and specifying the ProcessBreakOnTermination (0x1d) as ProcessInfoClass. In order to do this one must have the debug privilege assigned.

There are usually 3 processes that have this flag set on Windows 7:
smss.exe
csrss.exe
wininit.exe

But these processes can vary depending on the Windows version.

With the program you can remove the flag from any of the processes that have it configured, or you can set it on an arbitrary process. The program is compiled as a console application, and its syntax is:

ProcessCritical.exe -pid value -CriticalFlag value
-pid is the process id of target process
-CriticalFlag is the value to put into ProcessBreakOnTermination (0 or 1). 0 means process is not critical.

Example to remove the critical flag from smss.exe on my system (pid may vary of course):
ProcessCritical.exe -pid 244 -CriticalFlag 0

Example to set the critical flag to 1 for process with ID 2366:
ProcessCritical.exe -pid 2366 -CriticalFlag 1

Dump the critical flag configuration for all processes:
ProcessCritical.exe


Now if you want to know what happens if you remove the critical flag for any of those process that have it configured, and then terminate the process, then go ahead and try. I can tell you that your system will start behaving in a very strange way, and you will ultimately have no other choice than to do a hard reset of your system. Preferrably do this in virtual test machine. The only practical use of this, that I can think of is:
- a very nasty, rude, nonelegant and possibly devastating way of making sure your process stays with the system.
- ability to terminate processes that was initially marked as critical.

Attached is a PoC called BSOD.exe, that will simply BSOD your system. The point is that it sets the critical flag on itself, and then exit. That will instantly throw a Blue Screen Of Death.

Final words is to no surprise, that you need to be careful with this as you may crash your system, and it may become unbootable in certain cases. I take absolutely no responsibility for what you may cause with this code. You have been warned.

