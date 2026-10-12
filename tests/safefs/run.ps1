param([string]$TestPattern = '.', [string]$Image = 'hwh-safefs-lab:ticket01', [switch]$CheckOnly, [switch]$ScanOnly)
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$docker = (Get-Command docker -ErrorAction Stop).Source
$run = 'hwh01-' + [Guid]::NewGuid().ToString('N')
$volume = "$run-fixtures"
$result = Join-Path $project "test-artifacts/$run"
[IO.Directory]::CreateDirectory($result) | Out-Null
& $docker volume create --label hwh.safefs.lab=ticket01 $volume
if ($LASTEXITCODE -ne 0) { throw 'Could not create fresh fixture volume' }
try {
    & $docker run --name $run --label hwh.safefs.lab=ticket01 --network none --pids-limit 128 --memory 512m --cpus 2 --cap-drop ALL --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP --cap-add CHOWN --cap-add MKNOD --security-opt no-new-privileges --mount "type=volume,source=$volume,target=/fixture-store" --env "HWH_TEST_RUN=$run" --env "HWH_CHECK_ONLY=$([int]$CheckOnly.IsPresent)" --env "HWH_SCAN_ONLY=$([int]$ScanOnly.IsPresent)" $Image "-test.run=$TestPattern" 2>&1 | Tee-Object -FilePath (Join-Path $result 'tests.txt')
    $testExit = $LASTEXITCODE
    & $docker cp "${run}:/results/." $result
    if ($LASTEXITCODE -ne 0) { throw "Result capture failed; tests exited $testExit" }
    if ($testExit -ne 0) { throw "Linux tests failed ($testExit); see $result" }
    Write-Output "PASS: $result"
} finally {
    # Only resources uniquely created by this invocation are removed.
    & $docker rm -f $run
    & $docker volume rm $volume
}
