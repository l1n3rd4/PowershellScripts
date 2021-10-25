Function Update-MemoryAddresses
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [System.Object]
    $PEInfo,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [Int64]
    $OriginalImageBase,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [System.Object]
    $Win32Constants,
    
    [Parameter(Position = 3, Mandatory = $true)]
    [System.Object]
    $Win32Types
    )
    
    [Int64]$BaseDifference = 0
    $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
    [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
    
    #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
    if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
            -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
    {
        return
    }


    elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
    {
        $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
        $AddDifference = $false
    }
    elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
    {
        $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
    }
    
    #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
    [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
    while($true)
    {
        #If SizeOfBlock == 0, we are done
        $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

        if ($BaseRelocationTable.SizeOfBlock -eq 0)
        {
            break
        }

        [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
        $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

        #Loop through each relocation
        for($i = 0; $i -lt $NumRelocations; $i++)
        {
            #Get info for this relocation
            $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
            [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

            #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
            [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
            [UInt16]$RelocType = $RelocationInfo -band 0xF000
            for ($j = 0; $j -lt 12; $j++)
            {
                $RelocType = [Math]::Floor($RelocType / 2)
            }

            #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
            #This appears to be true for EXE's as well.
            #	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
            if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                    -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
            {			
                #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
    
                if ($AddDifference -eq $true)
                {
                    [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                }
                else
                {
                    [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                }				

                [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
            }
            elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
            {
                #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
            }
        }
        
        $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
    }
}