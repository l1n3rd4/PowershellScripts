Function Invoke-CreateRemoteThread
{
    Param(
    [Parameter(Position = 1, Mandatory = $true)]
    [IntPtr]
    $ProcessHandle,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [IntPtr]
    $StartAddress,
    
    [Parameter(Position = 3, Mandatory = $false)]
    [IntPtr]
    $ArgumentPtr = [IntPtr]::Zero,
    
    [Parameter(Position = 4, Mandatory = $true)]
    [System.Object]
    $Win32Functions
    )
    
    [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
    
    $OSVersion = [Environment]::OSVersion.Version
    #Vista and Win7
    if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
    {
        Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
        $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
        $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
        }
    }
    #XP/Win8
    else
    {
        Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
        $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
    }
    
    if ($RemoteThreadHandle -eq [IntPtr]::Zero)
    {
        Write-Verbose "Error creating remote thread, thread handle is null"
    }
    
    return $RemoteThreadHandle
}
