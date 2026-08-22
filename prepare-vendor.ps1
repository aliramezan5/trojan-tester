$ErrorActionPreference='Stop'
$Revision='04f46c6a0708418cb7b96fc563eacae0fbf77674'
$ExpectedGitBlob='993e88f396640f881b69f98db7a4d17401ef83ca'
$Url="https://raw.githubusercontent.com/davidshimjs/qrcodejs/$Revision/qrcode.min.js"
$Dir=Join-Path $PSScriptRoot 'vendor'
$File=Join-Path $Dir 'qrcode.js'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
function Get-GitBlobSha1([string]$Path){
  $bytes=[IO.File]::ReadAllBytes($Path);$prefix=[Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0");$all=New-Object byte[] ($prefix.Length+$bytes.Length);[Array]::Copy($prefix,0,$all,0,$prefix.Length);[Array]::Copy($bytes,0,$all,$prefix.Length,$bytes.Length);$sha=[Security.Cryptography.SHA1]::Create();try{return -join ($sha.ComputeHash($all)|ForEach-Object {$_.ToString('x2')})}finally{$sha.Dispose()}
}
$need=$true;if(Test-Path $File){$need=((Get-GitBlobSha1 $File) -ne $ExpectedGitBlob)}
if($need){Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $File}
if((Get-GitBlobSha1 $File) -ne $ExpectedGitBlob){Remove-Item $File -Force -ErrorAction SilentlyContinue;throw 'QRCode vendor verification failed'}
Write-Host 'QRCode vendor verified.'
