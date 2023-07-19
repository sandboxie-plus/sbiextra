Sbiextra dll from https://sandboxie-website-archive.github.io/www.sandboxie.com/old-forums/viewtopic7fcb7fcb.html?f=22&t=4885
is now open source big thanks to wraithdu for releaseing the source code.

# sbiextra

*** NOTE: You'll need the Microsoft Visual C++ 2008 SP1 Runtimes for the DLL to work. ***

I've created a DLL to block sandboxed processes from accessing information about processes running outside
the sandbox, and to prevent them from reading the memory of any process not running in their same sandbox.
This is accomplished by hooking several API functions:

- NtOpenProcess
- NtQuerySystemInformation
- NtReadVirtualMemory
- CreateToolhelp32Snapshot
- BlockInput
- InternalGetWindowText
- GetWindowTextA/W
- SendMessageA/W
	> WM_GETTEXT

The effects of using this DLL on sandboxed processes are as follows:

- block system-wide enumeration of running processes and threads (includes Toolhelp32 and PSAPI functions)
- block access to unsandboxed processes - cannot open processes, or read their memory
- prevent sandboxed processes from calling the BlockInput function (blocks mouse and keyboard input)
- prevent sandboxed processes from reading window titles or control text

To use it, download the DLL and save it somewhere. Then insert this line in your Sandboxie.ini file under the
sandbox you want to use the DLL.

32-bit platforms:
InjectDll=C:\some\path\to\sbiextra.dll

64-bit platforms add both:
InjectDll=C:\some\path\to\sbiextra.dll
InjectDll64=C:\some\path\to\sbiextra_x64.dll

On x64 platforms, both DLLs and directives should be used.  Sandboxie will inject the proper DLL depending on whether
the target process is 32-bit or 64-bit.

The DLL will be injected into any process running in the sandbox. That's it!


# Optional INI File:

To control which of the above functions are hooked in a sandboxed process, copy the provided 'sbiextra.ini' file
to the same directory as 'sbiextra.dll'.  For each function you want to hook, set the value to 1, for each
function you don't want hooked, set the value to 0.

Additionally, the DLL can output some debug information so you can see some of what is going on.  To output this
information, set the value of 'ShowDebugInfo' to 1.  To see the debug output, install and run Dbgview from
Sysinternals before starting a sandboxed process.


# Test Program:

Also included in the archive is a small test program. First it will attempt a system-wide process snapshot using
the Toolhelp32 API, then it will attempt to read 16 bytes from the base address of 'kernel32.dll' from the process
whose PID you provide on the commandline, and finally it will attempt a process module snapshot of the provided
PID using the Toolhelp32 API. To test, run 'injtest.exe' in the sandbox where you're injecting the DLL and provide
the PID of a sandboxed or unsandboxed process on the commandline. The system snapshot should fail (return a handle
of 0xFFFFFFFF). If the target process is unsandboxed, 'injtest.exe' will not be able to read it's memory or take a
snapshot. If it is sandboxed, the functions will succeed.

Next it will take a snapshot of all the windows on the system and try to get their titles via three different methods:
InternalGetWindowText, GetWindowTextW, and directly via SendMessageW with the WM_GETTEXT message.  Most of the
window titles should remain blank for all three tests.
