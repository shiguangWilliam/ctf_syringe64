# e2e.ps1 —— 端到端: puppet64(晚注入目标) + launcher 附着注入 + syrctl 控制面 +
#            宏登记 payload(reg篡改/跳过返回/任意跳转) 全链路验证。
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out  = Join-Path $root 'build'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'

function Invoke-Build([string]$label, [string]$cmdline) {
  $cmd = 'call "' + $vcvars + '" x64 >nul && ' + $cmdline
  cmd /c $cmd 2>&1 | Write-Host
  if ($LASTEXITCODE -ne 0) { throw "$label failed ($LASTEXITCODE)" }
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = Join-Path $out 'puppet64.exe'
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$puppet = [System.Diagnostics.Process]::Start($psi)
try {
  # 读取启动横幅
  $banner = @{}
  foreach ($k in 'BASE','ADD','SECRET','FLOW','ALT','PID') { $banner[$k] = $puppet.StandardOutput.ReadLine() }
  Write-Host ("puppet: " + ($banner.Values -join ' '))
  $base   = [Convert]::ToUInt64($banner['BASE'].Split('=')[1], 16)
  $pid_   = $banner['PID'].Split('=')[1]
  $addRva = [Convert]::ToUInt64($banner['ADD'].Split('=')[1], 16)    - $base
  $secRva = [Convert]::ToUInt64($banner['SECRET'].Split('=')[1], 16) - $base
  $flwRva = [Convert]::ToUInt64($banner['FLOW'].Split('=')[1], 16)   - $base
  $jmpAbs = [Convert]::ToUInt64($banner['ALT'].Split('=')[1], 16)    # 任意跳转目的地(未挂钩的 PuppetAlt)
  Write-Host ("rvas: add=+{0:x} secret=+{1:x} flow=+{2:x}" -f $addRva, $secRva, $flwRva)

  # 1) 附着注入牵引
  & (Join-Path $out 'launcher64.exe') --attach $pid_ (Join-Path $out 'syringe-tether.dll')
  if ($LASTEXITCODE -ne 0) { throw 'launcher attach failed' }

  # 2) 控制面握手
  & (Join-Path $out 'syrctl.exe') $pid_ hello
  if ($LASTEXITCODE -ne 0) { throw 'tether hello failed' }

  # 3) 编译宏登记 payload(注入真实 RVA/绝对地址)
  $pl = Join-Path $out 'e2e_payload.dll'
  Invoke-Build 'e2e payload' ("cl /nologo /LD /O2 /std:c++17 /source-charset:utf-8 /EHsc /W3 /I`"" + $root + "\include`" `"" + $root + "\example\payload_example.cpp`" " +
    "/DPUPPET_ADD_RVA=0x{0:x} /DPUPPET_SECRET_RVA=0x{1:x} /DPUPPET_FLOW_RVA=0x{2:x} /DPUPPET_JMP_ABS=0x{3:x} /Fe:`"$pl`"" -f $addRva, $secRva, $flwRva, $jmpAbs)

  # 4) 热加载 payload -> 自动安装宏钩子
  & (Join-Path $out 'syrctl.exe') $pid_ load $pl
  & (Join-Path $out 'syrctl.exe') $pid_ hooks
  & (Join-Path $out 'syrctl.exe') $pid_ log

  # 5) 行为验证
  function Puppet([string]$q) {
    $puppet.StandardInput.WriteLine($q)
    return $puppet.StandardOutput.ReadLine()
  }
  $fail = 0
  $r = Puppet 'add 1 2';       Write-Host "add 1 2 -> $r (want 103)";     if ($r -ne 'add=103') { $fail++ }
  $r = Puppet 'secret 1';      Write-Host "secret 1 -> $r (want 1337)";  if ($r -ne 'secret=1337') { $fail++ }
  $r = Puppet 'flow 5';        Write-Host "flow 5 -> $r (want 2468)"; if ($r -ne 'flow=2468') { $fail++ }
  if ($fail) { throw "e2e behavior checks failed ($fail)" }

  # 6) 操作员侧内存链路: alloc -> write -> read 回读一致
  $allocOut = & (Join-Path $out 'syrctl.exe') $pid_ alloc 64 0
  $memAddr = ($allocOut | Select-Object -First 1).Trim()
  Write-Host "alloc -> $memAddr"
  & (Join-Path $out 'syrctl.exe') $pid_ write $memAddr DEADBEEF | Out-Null
  $rd = (& (Join-Path $out 'syrctl.exe') $pid_ read $memAddr 4 | Select-Object -First 1).Trim()
  Write-Host "read back -> $rd (want DEADBEEF)"
  if ($rd -ne 'DEADBEEF') { throw 'e2e memory roundtrip failed' }
  & (Join-Path $out 'syrctl.exe') $pid_ free $memAddr | Out-Null

  # 7) 第二 payload 热加载(零钩子, 验证同进程追加 + 注入器零重编)
  $pl2 = Join-Path $out 'e2e_payload2.dll'
  Invoke-Build 'e2e payload2' ("cl /nologo /LD /O2 /std:c++17 /source-charset:utf-8 /EHsc /W3 /I`"" + $root + "\include`" `"" + $root + "\example\payload_second.cpp`" /Fe:`"$pl2`"")
  & (Join-Path $out 'syrctl.exe') $pid_ load $pl2 | Out-Null
  $log2 = & (Join-Path $out 'syrctl.exe') $pid_ log
  if (-not ($log2 -match 'payload_second: alive')) { throw 'e2e second payload failed' }
  Write-Host 'second payload hot-load OK (injector untouched)'

  # 8) 冻结/解冻冒烟
  & (Join-Path $out 'syrctl.exe') $pid_ freeze
  & (Join-Path $out 'syrctl.exe') $pid_ thaw
  [void](Puppet 'add 3 4')

  Puppet 'quit' | Out-Null
  $puppet.WaitForExit(5000) | Out-Null
} finally {
  if (-not $puppet.HasExited) { $puppet.Kill() }
}
Write-Host 'e2e PASS'
exit 0
