# e2e_create.ps1 —— --create 模式冒烟: suspended 创建 + 注入 + resume,
#                  验证牵引在无 stdin 的子进程里正常起来(管道 + Web UI 双控制面)。
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out  = Join-Path $root 'build'
$smoke = Join-Path $out 'create_smoke.txt'

$env:PUPPET_HOLD = '1'
try {
  $p = Start-Process -FilePath (Join-Path $out 'launcher64.exe') `
       -ArgumentList @('--create', (Join-Path $out 'puppet64.exe'), '--',
                       (Join-Path $out 'syringe-tether.dll')) `
       -RedirectStandardOutput $smoke -RedirectStandardError "$smoke.err" `
       -PassThru -NoNewWindow
  # 等子进程(真实目标 puppet)打出横幅
  $pid_ = $null
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if (Test-Path $smoke) {
      $txt = Get-Content $smoke -Raw -ErrorAction SilentlyContinue
      if ($txt -match 'PID=(\d+)') { $pid_ = $Matches[1]; break }
    }
  }
  if (-not $pid_) { throw 'create smoke: no banner/pid from puppet' }
  Write-Host "create smoke: puppet pid=$pid_"

  & (Join-Path $out 'syrctl.exe') $pid_ hello
  if ($LASTEXITCODE -ne 0) { throw 'create smoke: pipe hello failed' }

  # Web UI 控制面
  $port = 18700 + ([int]$pid_ % 256)
  $resp = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/api/exec?c=hello").Content
  Write-Host "web ui :$port -> $($resp.Split("`n")[0])"
  if ($resp -notmatch 'syringe64 tether') { throw 'create smoke: web hello failed' }
  $page = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/").Content
  if ($page -notmatch 'syringe64 tether') { throw 'create smoke: dashboard missing' }
  Write-Host 'web dashboard OK'

  Stop-Process -Id ([int]$pid_) -Force -ErrorAction SilentlyContinue
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
} finally {
  Remove-Item Env:PUPPET_HOLD -ErrorAction SilentlyContinue
  Get-Process puppet64 -ErrorAction SilentlyContinue | Stop-Process -Force
}
Write-Host 'create smoke PASS'
exit 0
