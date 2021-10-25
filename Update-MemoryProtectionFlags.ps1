Function Update-MemoryProtectionFlags
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
    [System.Object]
    $Win32Types
    )
    
    for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
    {
        [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
        $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
        [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
        
        [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
        [UInt32]$SectionSize = $SectionHeader.VirtualSize
        
        [UInt32]$OldProtectFlag = 0
        Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
        $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
        if ($Success -eq $false)
        {
            Throw "Unable to change memory protection"
        }
    }
}