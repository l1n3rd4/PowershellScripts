#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
Function Update-ExeFunctions
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [System.Object]
    $PEInfo,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $Win32Functions,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [System.Object]
    $Win32Constants,
    
    [Parameter(Position = 3, Mandatory = $true)]
    [String]
    $ExeArguments,
    
    [Parameter(Position = 4, Mandatory = $true)]
    [IntPtr]
    $ExeDoneBytePtr
    )
    
    #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
    $ReturnArray = @() 
    
    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    [UInt32]$OldProtectFlag = 0
    
    [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
    if ($Kernel32Handle -eq [IntPtr]::Zero)
    {
        throw "Kernel32 handle null"
    }
    
    [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
    if ($KernelBaseHandle -eq [IntPtr]::Zero)
    {
        throw "KernelBase handle null"
    }

    #################################################
    #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
    #	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
    $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
    $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

    [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
    [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

    if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
    {
        throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
    }

    #Prepare the shellcode
    [Byte[]]$Shellcode1 = @()
    if ($PtrSize -eq 8)
    {
        $Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
    }
    $Shellcode1 += 0xb8
    
    [Byte[]]$Shellcode2 = @(0xc3)
    $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
    
    
    #Make copy of GetCommandLineA and GetCommandLineW
    $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
    $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
    $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
    $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
    $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
    $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

    #Overwrite GetCommandLineA
    [UInt32]$OldProtectFlag = 0
    $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
    if ($Success = $false)
    {
        throw "Call to VirtualProtect failed"
    }
    
    $GetCommandLineAAddrTemp = $GetCommandLineAAddr
    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
    $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
    $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
    
    $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
    
    
    #Overwrite GetCommandLineW
    [UInt32]$OldProtectFlag = 0
    $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
    if ($Success = $false)
    {
        throw "Call to VirtualProtect failed"
    }
    
    $GetCommandLineWAddrTemp = $GetCommandLineWAddr
    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
    $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
    $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
    
    $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
    #################################################
    
    
    #################################################
    #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
    #	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
    #	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
    #	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
    $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
        , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
    
    foreach ($Dll in $DllList)
    {
        [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
        if ($DllHandle -ne [IntPtr]::Zero)
        {
            [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
            [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
            if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
            {
                "Error, couldn't find _wcmdln or _acmdln"
            }
            
            $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
            $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
            
            #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
            $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
            $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
            $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
            $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
            $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
            
            $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
            if ($Success = $false)
            {
                throw "Call to VirtualProtect failed"
            }
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
            $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            
            $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
            if ($Success = $false)
            {
                throw "Call to VirtualProtect failed"
            }
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
            $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
        }
    }
    #################################################
    
    
    #################################################
    #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

    $ReturnArray = @()
    $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
    
    #CorExitProcess (compiled in to visual studio c++)
    [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
    if ($MscoreeHandle -eq [IntPtr]::Zero)
    {
        throw "mscoree handle null"
    }
    [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
    if ($CorExitProcessAddr -eq [IntPtr]::Zero)
    {
        Throw "CorExitProcess address not found"
    }
    $ExitFunctions += $CorExitProcessAddr
    
    #ExitProcess (what non-managed programs use)
    [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
    if ($ExitProcessAddr -eq [IntPtr]::Zero)
    {
        Throw "ExitProcess address not found"
    }
    $ExitFunctions += $ExitProcessAddr
    
    [UInt32]$OldProtectFlag = 0
    foreach ($ProcExitFunctionAddr in $ExitFunctions)
    {
        $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
        #The following is the shellcode (Shellcode: ExitThread.asm):
        #32bit shellcode
        [Byte[]]$Shellcode1 = @(0xbb)
        [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
        #64bit shellcode (Shellcode: ExitThread.asm)
        if ($PtrSize -eq 8)
        {
            [Byte[]]$Shellcode1 = @(0x48, 0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
        }
        [Byte[]]$Shellcode3 = @(0xff, 0xd3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
        
        [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
        if ($ExitThreadAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitThread address not found"
        }

        $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
        if ($Success -eq $false)
        {
            Throw "Call to VirtualProtect failed"
        }
        
        #Make copy of original ExitProcess bytes
        $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
        
        #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
        #	call ExitThread
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
        $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
        $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
        $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
        $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

        $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
    }
    #################################################

    Write-Output $ReturnArray
}