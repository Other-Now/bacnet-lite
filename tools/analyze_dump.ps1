# Run cdb (WinDbg's console engine) over a bl-device minidump and print the
# standard first look: !analyze -v, the exception context, the stack with source
# lines, and the faulting frame's locals.
#
#   powershell -File tools\analyze_dump.ps1 -Dump <file.dmp> [-Bin build-msvc-plant] [-Commands "..."]
#
# The PDBs must come from the same build as the crashed binary; Microsoft's symbol
# server supplies ntdll/kernel32/ucrtbase.
param(
    [Parameter(Mandatory)] [string] $Dump,
    [string] $Bin = 'build-msvc-plant',
    [string] $Commands = '!analyze -v; .ecxr; kn 10; .frame 0; dv /t; .frame 1; dv /t',
    [string] $Cdb = ''
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Cdb) {
    $pkg = Get-AppxPackage Microsoft.WinDbg -ErrorAction SilentlyContinue
    if ($pkg) { $Cdb = Join-Path $pkg.InstallLocation 'amd64\cdb.exe' }
    if (-not $Cdb -or -not (Test-Path $Cdb)) { throw 'cdb.exe not found (winget install Microsoft.WinDbg) or pass -Cdb' }
}
$binDir = Join-Path $root $Bin
$symcache = Join-Path $env:LOCALAPPDATA 'symcache'
$sym = "$binDir;srv*$symcache*https://msdl.microsoft.com/download/symbols"
$out = & $Cdb -z $Dump -y $sym -i $binDir -srcpath $root -lines -c "$Commands; q" 2>&1
$started = $false
foreach ($line in $out) {
    $s = "$line"
    if (-not $started) {
        if ($s -match 'This dump file has an exception|Reading initial command') { $started = $true } else { continue }
    }
    if ($s -match 'NatVis script|Whitespace at start of path|^quit:|Unable to verify checksum|^\s*$') { continue }
    $s
}
