# REMOTE_THREAD_SUSPENDED-PROCESS-INJECTION

- REMOTE_THREAD_SUSPENDED PROCESS INJECTION
-- description: |
	* Injects shellcode into a newly spawned remote process and flips memory protection to PAGE_NOACCESS. 
	* After a short sleep (waiting until a possible AV scan is finished) the protection is flipped again to PAGE_EXECUTE_READ.
	* Thread execution via ResumeThread.
	
-------------------------------------------
key win32 API calls:
  - kernel32.dll:
    1: 'OpenProcess'
    2: 'VirtualAllocEx (PAGE_EXECUTE_READ_WRITE)'
    3: 'WriteProcessMemory'
    4: 'VirtualProtectEx (PAGE_NO_ACCESS)'
    5: 'CreateRemoteThread (CREATE_SUSPENDED)'
    6: 'ResumeThread'
--------------------------------------------
