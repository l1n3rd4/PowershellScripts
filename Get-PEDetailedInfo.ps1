#PEInfo must contain the following NoteProperties:
#	PEHandle: An IntPtr to the address the PE is loaded to in memory
Function Get-PEDetailedInfo
{
    Param(
    [Parameter( Position = 0, Mandatory = $true)]
    [IntPtr]
    $PEHandle,
    
    [Parameter(Position = 1, Mandatory = $true)]
    [System.Object]
    $Win32Types,
    
    [Parameter(Position = 2, Mandatory = $true)]
    [System.Object]
    $Win32Constants
    )
    
    if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
    {
        throw 'PEHandle is null or IntPtr.Zero'
    }
    
    $PEInfo = New-Object System.Object
    
    #Get NtHeaders information
    $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
    
    #Build the PEInfo object
    $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
    $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
    $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
    $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
    
    if ($PEInfo.PE64Bit -eq $true)
    {
        [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
        $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
    }
    else
    {
        [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
        $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
    }
    
    if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
    {
        $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
    }
    elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
    }
    else
    {
        Throw "PE file is not an EXE or DLL"
    }
    
    return $PEInfo
}