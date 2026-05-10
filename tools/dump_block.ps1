param(
    [string]$File = "svf_disk.img",
    [int]$Block = 35,
    [int]$BlockSize = 4096,
    [int]$Bytes = 64
)

$offset = [int64]$Block * [int64]$BlockSize
if (-not (Test-Path $File)) {
    Write-Host "MISSING: $File"
    exit 2
}

try {
    $fs = [System.IO.File]::OpenRead($File)
    $fs.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $buf = New-Object byte[] $Bytes
    $r = $fs.Read($buf, 0, $buf.Length)
    Write-Host "READ=$r"
    if ($r -gt 0) {
        $hex = ($buf[0..($r-1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Host "HEX=$hex"
    } else {
        Write-Host "HEX=EMPTY"
    }
    $fs.Close()
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}
exit 0
