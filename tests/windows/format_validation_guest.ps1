# Module: tests.windows.format_validation_guest
# Purpose: Validate generated NTFS geometry cases in a disposable Windows guest.
# Created: 2026-10-02
# Architecture: prepare_format_validation.py renders the case manifest into this template;
# native Windows tools inspect each disk.

param([switch]$Shutdown)
$ErrorActionPreference='Stop'
$runId='@RUN_ID@'
$cases=ConvertFrom-Json '@CASES_JSON@'
Start-Transcript -Path "C:\$runId.txt" -Force
try {
 "RUN_ID=$runId"
 $os=Get-CimInstance Win32_OperatingSystem
 "WINDOWS_BUILD=$($os.BuildNumber)"
 foreach($case in $cases) {
  $disks=@(Get-Disk | Where-Object { $_.Signature -eq $case.signature })
  if($disks.Count -ne 1 -or $disks[0].Size -ne 68157440 -or $disks[0].LogicalSectorSize -ne $case.sector) { throw 'Wrong disposable disk/sector size' }
  $part=Get-Partition -DiskNumber $disks[0].Number | Where-Object { $_.Type -eq 'IFS' }
  if(!$part.DriveLetter){$part | Add-PartitionAccessPath -AssignDriveLetter;$part=Get-Partition -DiskNumber $disks[0].Number -PartitionNumber $part.PartitionNumber}
  $drive="$($part.DriveLetter):"
  "CASE=$($case.name);DRIVE=$drive"
  & fsutil.exe dirty query $drive
  & chkdsk.exe $drive
  'CHKDSK_BEFORE='+$LASTEXITCODE
  $bytes=[IO.File]::ReadAllBytes($drive+'\geometry.bin')
  if($bytes.Length -ne 76800){throw 'Incorrect length'}
  for($i=0;$i -lt $bytes.Length;$i++){if($bytes[$i] -ne ($i%256)){throw 'Incorrect content'}}
  'GEOMETRY_CONTENT=OK'
  [IO.File]::WriteAllText($drive+'\windows.txt','native Rust formatter Windows validation')
  'CONTENT='+[IO.File]::ReadAllText($drive+'\windows.txt')
  & chkdsk.exe $drive
  'CHKDSK_AFTER='+$LASTEXITCODE
 }
 $events=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$os.LastBootUpTime} | Where-Object { $_.ProviderName -eq 'Ntfs' })
 foreach($event in $events){'NTFS_EVENT='+($event.ToXml() -replace "`r?`n",' ')}
 "RUN_COMPLETE=$runId"
} catch { 'RUN_ERROR='+$_ } finally { Stop-Transcript; if($Shutdown){shutdown.exe /s /t 0} }
