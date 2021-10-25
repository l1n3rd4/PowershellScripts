Function Get-MemoryProcAddress
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [IntPtr]
    $PEHandle,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [String]
    $FunctionName
    )
    
    $Win32Types = Get-Win32Types
    $Win32Constants = Get-Win32Constants
    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
    
    #Get the export table
    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
    {
        return [IntPtr]::Zero
    }
    $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
    $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
    
    for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
    {
        #AddressOfNames is an array of pointers to strings of the names of the functions exported
        $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
        $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
        $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

        if ($Name -ceq $FunctionName)
        {
            #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
            #    which contains the offset of the function in to the DLL
            $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
            $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
            $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
            return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
        }
    }
    
    return [IntPtr]::Zero
}