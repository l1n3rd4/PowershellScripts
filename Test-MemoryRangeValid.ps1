Function Test-MemoryRangeValid
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [String]
    $DebugString,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $PEInfo,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [IntPtr]
    $StartAddress,
    
    [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
    [IntPtr]
    $Size
    )
    
    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
    
    $PEEndAddress = $PEInfo.EndAddress
    
    if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
    {
        Throw "Trying to write to memory smaller than allocated address range. $DebugString"
    }
    if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
    {
        Throw "Trying to write to memory greater than allocated address range. $DebugString"
    }
}