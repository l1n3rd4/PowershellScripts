Function Get-RemoteProcAddress
{
    Param(
    [Parameter(Position=0, Mandatory=$true)]
    [IntPtr]
    $RemoteProcHandle,
    
    [Parameter(Position=1, Mandatory=$true)]
    [IntPtr]
    $RemoteDllHandle,
    
    [Parameter(Position=2, Mandatory=$true)]
    [String]
    $FunctionName
    )

    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
    $FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
    
    #Write FunctionName to memory (will be used in GetProcAddress)
    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
    if ($RFuncNamePtr -eq [IntPtr]::Zero)
    {
        Throw "Unable to allocate memory in the remote process"
    }

    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
    if ($Success -eq $false)
    {
        Throw "Unable to write DLL path to remote process memory"
    }
    if ($FunctionNameSize -ne $NumBytesWritten)
    {
        Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
    }
    
    #Get address of GetProcAddress
    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
    $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

    
    #Allocate memory for the address returned by GetProcAddress
    $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
    if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
    {
        Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
    }
    
    
    #Write Shellcode to the remote process which will call GetProcAddress
    #Shellcode: GetProcAddress.asm
    #todo: need to have detection for when to get by ordinal
    [Byte[]]$GetProcAddressSC = @()
    if ($PEInfo.PE64Bit -eq $true)
    {
        $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
        $GetProcAddressSC2 = @(0x48, 0xba)
        $GetProcAddressSC3 = @(0x48, 0xb8)
        $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
        $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
    }
    else
    {
        $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
        $GetProcAddressSC2 = @(0xb9)
        $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
        $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
        $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
    }
    $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
    $SCPSMemOriginal = $SCPSMem
    
    Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
    Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
    Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
    Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
    Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
    
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
    
    #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
    [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
    $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
    if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
    {
        Throw "Call to ReadProcessMemory failed"
    }
    [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
    
    return $ProcAddress
}
