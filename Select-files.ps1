$server = ''

$serverAfter = ''

# $blackList = ''

function Select-files{
    param(
        $srv
    )

    PROCESS{
        $ActualDate = Get-Date
        $NumberDays = 2

        $dir = Get-ChildItem $srv

        $dir | ForEach-Object {

            if($_.Attributes -eq "Directory"){
                Select-files $_.FullName
            } else {

                $alt = $ActualDate - $_.LastWriteTime
                
                if($alt.Days -ge $NumberDays){

                   $serverFinal = $serverAfter + $_.Directory.Name 

                   if(!(Test-Path -Path $serverFinal)){
                        New-Item -Path $serverFinal -ItemType "directory"
                   }

                   Move-Item -Path $_.FullName -Destination $serverFinal
                }
            }
        }
    }
}

Select-files $server