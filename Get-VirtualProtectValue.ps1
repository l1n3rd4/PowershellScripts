Function Get-VirtualProtectValue
{
    Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [UInt32]
    $SectionCharacteristics
    )
    
    $ProtectionFlag = 0x0
    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
    {
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
            {
                $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
            }
            else
            {
                $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
            {
                $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
            }
            else
            {
                $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
            }
        }
    }
    else
    {
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
            {
                $ProtectionFlag = $Win32Constants.PAGE_READWRITE
            }
            else
            {
                $ProtectionFlag = $Win32Constants.PAGE_READONLY
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
            {
                $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
            }
            else
            {
                $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
            }
        }
    }
    
    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
    {
        $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
    }
    
    return $ProtectionFlag
}