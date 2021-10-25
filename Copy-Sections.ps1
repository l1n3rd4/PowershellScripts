Function Copy-Sections
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [Byte[]]
    $PEBytes,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $PEInfo,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [System.Object]
    $Win32Functions,
    
    [Parameter(Position = 3, Mandatory = $true)]
    [System.Object]
    $Win32Types
    )
    
    for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
    {
        [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
        $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
    
        #Address to copy the section to
        [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
        
        #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
        #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
        #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
        #    so truncate SizeOfRawData to VirtualSize
        $SizeOfRawData = $SectionHeader.SizeOfRawData

        if ($SectionHeader.PointerToRawData -eq 0)
        {
            $SizeOfRawData = 0
        }
        
        if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
        {
            $SizeOfRawData = $SectionHeader.VirtualSize
        }
        
        if ($SizeOfRawData -gt 0)
        {
            Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
            [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
        }
    
        #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
        if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
        {
            $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
            [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
            Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
            $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
        }
    }
}