Function Get-PEBasicInfo
{
    Param(
    [Parameter( Position = 0, Mandatory = $true )]
    [Byte[]]
    $PEBytes,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $Win32Types
    )
    
    $PEInfo = New-Object System.Object
    
    #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
    [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
    
    #Get NtHeadersInfo
    $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
    
    #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
    $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
    $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
    $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
    
    #Free the memory allocated above, this isn't where we allocate the PE to memory
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
    
    return $PEInfo
}