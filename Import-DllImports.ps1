Function Import-DllImports
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
    $Win32Types,
    
    [Parameter(Position = 3, Mandatory = $true)]
    [System.Object]
    $Win32Constants,
    
    [Parameter(Position = 4, Mandatory = $false)]
    [IntPtr]
    $RemoteProcHandle
    )
    
    $RemoteLoading = $false
    if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
    {
        $RemoteLoading = $true
    }
    
    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
    {
        [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
        
        while ($true)
        {
            $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
            
            #If the structure is null, it signals that this is the end of the array
            if ($ImportDescriptor.Characteristics -eq 0 `
                    -and $ImportDescriptor.FirstThunk -eq 0 `
                    -and $ImportDescriptor.ForwarderChain -eq 0 `
                    -and $ImportDescriptor.Name -eq 0 `
                    -and $ImportDescriptor.TimeDateStamp -eq 0)
            {
                Write-Verbose "Done importing DLL imports"
                break
            }

            $ImportDllHandle = [IntPtr]::Zero
            $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
            $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
            
            if ($RemoteLoading -eq $true)
            {
                $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
            }
            else
            {
                $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
            }

            if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
            {
                throw "Error importing DLL, DLLName: $ImportDllPath"
            }
            
            #Get the first thunk, then loop through all of them
            [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
            [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
            [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
            
            while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
            {
                $ProcedureName = ''
                #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                #	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                #	and doing the comparison, just see if it is less than 0
                [IntPtr]$NewThunkRef = [IntPtr]::Zero
                if([Int64]$OriginalThunkRefVal -lt 0)
                {
                    $ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                }
                else
                {
                    [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                    $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                    $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                }
                
                if ($RemoteLoading -eq $true)
                {
                    [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
                }
                else
                {
                    if($ProcedureName -is [string])
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressOrdinal.Invoke($ImportDllHandle, $ProcedureName)
                    }
                }
                
                if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                {
                    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                }

                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                
                $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
            }
            
            $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
        }
    }
}