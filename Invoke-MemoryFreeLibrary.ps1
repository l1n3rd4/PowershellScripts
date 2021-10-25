Function Invoke-MemoryFreeLibrary
{
    Param(
    [Parameter(Position=0, Mandatory=$true)]
    [IntPtr]
    $PEHandle
    )
    
    #Get Win32 constants and functions
    $Win32Constants = Get-Win32Constants
    $Win32Functions = Get-Win32Functions
    $Win32Types = Get-Win32Types
    
    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
    
    #Call FreeLibrary for all the imports of the DLL
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
                Write-Verbose "Done unloading the libraries needed by the PE"
                break
            }

            $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
            $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

            if ($ImportDllHandle -eq $null)
            {
                Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
            }
            
            $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
            }
            
            $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
        }
    }
    
    #Call DllMain with process detach
    Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
    $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
    $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
    $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
    
    $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
    
    
    $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
    if ($Success -eq $false)
    {
        Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
    }
}