Function Write-BytesToMemory
{
    Param(
        [Parameter(Position=0, Mandatory = $true)]
        [Byte[]]
        $Bytes,
        
        [Parameter(Position=1, Mandatory = $true)]
        [IntPtr]
        $MemoryAddress
    )

    for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
    {
        [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
    }
}