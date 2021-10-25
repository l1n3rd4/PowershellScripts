#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
#	It copies Count bytes from Source to Destination.
Function Copy-ArrayOfMemAddresses
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [Array[]]
    $CopyInfo,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $Win32Functions,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [System.Object]
    $Win32Constants
    )

    [UInt32]$OldProtectFlag = 0
    foreach ($Info in $CopyInfo)
    {
        $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
        if ($Success -eq $false)
        {
            Throw "Call to VirtualProtect failed"
        }
        
        $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
        
        $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
    }
}