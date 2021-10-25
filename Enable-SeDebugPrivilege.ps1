Function Enable-SeDebugPrivilege
{
    Param(
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $Win32Functions,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [System.Object]
    $Win32Types,
    
    [Parameter(Position = 3, Mandatory = $true)]
    [System.Object]
    $Win32Constants
    )
    
    [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
    if ($ThreadHandle -eq [IntPtr]::Zero)
    {
        Throw "Unable to get the handle to the current thread"
    }
    
    [IntPtr]$ThreadToken = [IntPtr]::Zero
    [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
    if ($Result -eq $false)
    {
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
        {
            $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
            if ($Result -eq $false)
            {
                Throw "Unable to impersonate self"
            }
            
            $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
            if ($Result -eq $false)
            {
                Throw "Unable to OpenThreadToken."
            }
        }
        else
        {
            Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
        }
    }
    
    [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
    $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
    if ($Result -eq $false)
    {
        Throw "Unable to call LookupPrivilegeValue"
    }

    [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
    [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
    $TokenPrivileges.PrivilegeCount = 1
    $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
    $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

    $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
    if (($Result -eq $false) -or ($ErrorCode -ne 0))
    {
        #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
    }
    
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
}