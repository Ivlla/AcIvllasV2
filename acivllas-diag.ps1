param([string]$Label = "snapshot")
$cands = Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'"
$pick = $cands | Where-Object { $_.CommandLine -match 'forgeclient|--gameDir|modlauncher' } | Select-Object -First 1
if (-not $pick) { $pick = $cands | Select-Object -First 1 }
if (-not $pick) { Write-Host "java process not found"; exit 1 }
$proc = Get-Process -Id $pick.ProcessId
$cmd = $pick.CommandLine
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class AcMem {
  [StructLayout(LayoutKind.Sequential)] public struct MBI {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
    public ushort PartitionId; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
  [DllImport("kernel32.dll")] public static extern IntPtr VirtualQueryEx(IntPtr p, IntPtr a, out MBI b, IntPtr l);
}
"@
$L = New-Object System.Collections.Generic.List[string]
$L.Add("Java processes: " + (($cands | ForEach-Object { "$($_.ProcessId):$($_.Name)" }) -join ', '))
$L.Add("PID $($proc.Id), start $($proc.StartTime)")
$L.Add("JVM flags: " + (([regex]::Matches($cmd,'-(javaagent|agentlib|agentpath|XX|Xbootclasspath)\S*') | ForEach-Object { $_.Value }) -join ' '))
$L.Add("--- MODULES (path | size | signature)")
$ranges = @()
foreach ($m in $proc.Modules) {
  $b = [UInt64]$m.BaseAddress.ToInt64(); $ranges += [pscustomobject]@{S=$b; E=$b+$m.ModuleMemorySize}
  $sig = (Get-AuthenticodeSignature -LiteralPath $m.FileName -ErrorAction SilentlyContinue).Status
  $L.Add("$($m.FileName) | $($m.ModuleMemorySize) | $sig")
}
$L.Add("--- THREADS with start address outside any module")
foreach ($t in $proc.Threads) {
  $a = [UInt64]$t.StartAddress.ToInt64()
  if (-not ($ranges | Where-Object { $a -ge $_.S -and $a -lt $_.E })) { $L.Add(("TID {0} start 0x{1:X} {2}" -f $t.Id, $a, $t.ThreadState)) }
}
$L.Add("--- PRIVATE EXECUTABLE REGIONS (base | size | protect)")
$sz = [Runtime.InteropServices.Marshal]::SizeOf([type]'AcMem+MBI'); $addr = [UInt64]0; $n = 0
while ($addr -lt 0x7FFFFFFFFFFF) {
  $mbi = New-Object 'AcMem+MBI'
  if ([AcMem]::VirtualQueryEx($proc.Handle, [IntPtr][Int64]$addr, [ref]$mbi, [IntPtr]$sz) -eq [IntPtr]::Zero) { break }
  $len = [UInt64]$mbi.RegionSize.ToInt64(); $p = $mbi.Protect -band 0xFF
  if ($mbi.State -eq 0x1000 -and $mbi.Type -eq 0x20000 -and (0x10,0x20,0x40,0x80 -contains $p)) {
    $n++; $L.Add(("0x{0:X} | {1} | 0x{2:X}" -f [UInt64]$mbi.BaseAddress.ToInt64(), $len, $p)) }
  $addr = [UInt64]$mbi.BaseAddress.ToInt64() + $len
}
$L.Add("regions: $n")
$out = Join-Path ([Environment]::GetFolderPath("Desktop")) "acivllas-diag-$Label.txt"
$L | Set-Content -Encoding UTF8 $out
Write-Host "Done: $out"