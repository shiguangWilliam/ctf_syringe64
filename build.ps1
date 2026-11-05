# ctf-syringe64 一期构建: core/tether/launcher/syrctl/puppet/selftest + e2e
# 需要 VS BuildTools vcvarsall.bat(x64)。产物都在 build\。
$ErrorActionPreference = 'Stop'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found" }
$root  = $PSScriptRoot
$out   = Join-Path $root 'build'
$obj   = Join-Path $out 'obj'
$inc   = Join-Path $root 'include'
$mh    = Join-Path $root 'vendor\minhook'
$corei = Join-Path $root 'src\core'
foreach ($d in @('obj\mh', 'obj\tether', 'test')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $out $d) | Out-Null
}

function Invoke-Build([string]$label, [string]$cmdline) {
  Write-Host "== $label =="
  $cmd = 'call "' + $vcvars + '" x64 >nul && ' + $cmdline
  cmd /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "$label failed ($LASTEXITCODE)" }
}

# ---- MinHook(vendor, 不修改) ----
Invoke-Build 'minhook' "cl /nologo /c /O2 /I`"$mh\include`" `"$mh\src\buffer.c`" `"$mh\src\hook.c`" `"$mh\src\trampoline.c`" `"$mh\src\hde\hde32.c`" `"$mh\src\hde\hde64.c`" /Fo:$obj\mh\"

# ---- core(MinHook 薄封装, 静态库) ----
Invoke-Build 'core cpp' "cl /nologo /c /std:c++17 /source-charset:utf-8 /EHsc /W3 /O2 /I`"$inc`" /I`"$mh\include`" `"$root\src\core\syr_core.cpp`" /Fo:`"$obj\syr_core.obj`""
Invoke-Build 'core lib' "lib /nologo /OUT:`"$obj\syr_core.lib`" `"$obj\syr_core.obj`" $obj\mh\*.obj"

# ---- tether dll ----
Invoke-Build 'tether.dll' "cl /nologo /LD /std:c++17 /source-charset:utf-8 /EHsc /W3 /O2 /I`"$inc`" /I`"$corei`" /I`"$mh\include`" `"$root\src\tether\tether_main.cpp`" `"$obj\syr_core.lib`" /Fe:`"$out\syringe-tether.dll`" /Fo:$obj\tether\ /link psapi.lib ws2_32.lib"

# ---- launcher / ctl ----
Invoke-Build 'launcher64' "cl /nologo /O2 /std:c++17 /source-charset:utf-8 /EHsc /W3 `"$root\src\launcher\launcher_main.cpp`" /Fe:`"$out\launcher64.exe`" /Fo:`"$obj\launcher.obj`""
Invoke-Build 'syrctl'     "cl /nologo /O2 /std:c++17 /source-charset:utf-8 /EHsc /W3 `"$root\src\ctl\syrctl.cpp`" /Fe:`"$out\syrctl.exe`" /Fo:`"$obj\syrctl.obj`""

# ---- puppet64 / selftest ----
Invoke-Build 'puppet64' "cl /nologo /O2 /std:c++17 /source-charset:utf-8 /EHsc /W3 `"$root\test\puppet_main.cpp`" /Fe:`"$out\puppet64.exe`" /Fo:`"$obj\puppet.obj`""
Invoke-Build 'selftest' "cl /nologo /Od /GS- /std:c++17 /source-charset:utf-8 /EHsc /W3 /I`"$inc`" /I`"$corei`" `"$root\test\selftest.cpp`" `"$obj\syr_core.lib`" /Fe:`"$out\selftest.exe`" /Fo:`"$out\test\selftest.obj`" /link psapi.lib"

& (Join-Path $out 'selftest.exe')
if ($LASTEXITCODE -ne 0) { throw 'selftest failed' }
Write-Host 'build + selftest OK'

& (Join-Path $root 'test\e2e.ps1')
if ($LASTEXITCODE -ne 0) { throw 'e2e failed' }
Write-Host 'e2e OK'

& (Join-Path $root 'test\e2e_create.ps1')
if ($LASTEXITCODE -ne 0) { throw 'e2e create smoke failed' }
Write-Host 'e2e create smoke OK'
