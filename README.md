### KnownDllUnhook: Replace the .txt section of the current loaded modules from \KnownDlls\ to do api unhooking


### How Does it Work:
  - first, it loops through the loaded dlls
  - check if the name of the loaded dll is found in \KnownDlls\ dir
  - if found, the dll will be mapped to the current process
  - then, some calculations happen ( to get the address of the .txt section of the current dll & it's size )
  - change the memory permissions on current dll's .txt to 'PAGE_EXECUTE_WRITECOPY'
  - replace the .txt section from our \KnownDlls\ dll
  - fix the memory protection back to what it was
  - unmap the \KnownDlls\ dll since it is no longer needed
  - continue the loop until all the current dlls are checked 
  - all the intial syscalls ( the ones that do the unhooking ) are from [Syscallslib](https://github.com/ORCx41/Syscallslib) 



### Demo:

![image](https://user-images.githubusercontent.com/111295429/192698910-ed27f5e5-30dd-4df8-be44-9bf8920c3f6b.jpg)




<br>

### Note that this idea isnt mine, its my implementation only ...
### Based On:
  - https://github.com/rad9800/WTSRM
  
  
 
  
