
$application = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Office*"}

foreach($app in $application){
    $app.Uninstall()
}

$username=''
$password= ""  
$ftp='ftp://ftp.direcional.com.br'
$remote_file='/OFFICE HOMOLOGADO/SETUPS/OFFICE 2010 HOME AND BUSINESS/Office_HB_2010_Brazilian_x32.exe'
$local_file = 'C:\office.exe'

$ftpuri = $ftp + $remote_file
$uri=[system.URI] $ftpuri
$ftprequest=[system.net.ftpwebrequest]::Create($uri)
$ftprequest.Credentials=New-Object System.Net.NetworkCredential($username,$password)

$ftprequest.Method=[system.net.WebRequestMethods+ftp]::DownloadFile
$ftprequest.UseBinary = $true
$ftprequest.KeepAlive = $false

$response=$ftprequest.GetResponse()
$strm=$response.GetResponseStream()

try{
    $targetfile = New-Object IO.FileStream ($local_file,[IO.FileMode]::Create)
    "File created: $local_file"
    [byte[]]$readbuffer = New-Object byte[] 1024
    
    do{
        $readlength = $strm.Read($readbuffer,0,1024)
        $targetfile.Write($readbuffer,0,$readlength)
    }while ($readlength -ne 0)

    $targetfile.close()
} catch {
    $_| fl * -Force
}

Set-location -Path "C:\"
& '.\office.exe' /sAll /msi /norestart ALLUSERS=1 EULA_ACCEPT=YES
