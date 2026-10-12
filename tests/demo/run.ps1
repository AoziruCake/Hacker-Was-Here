param([string]$Image = 'hwh-safefs-lab:ticket13')
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$docker = (Get-Command docker -ErrorAction Stop).Source
$run = 'hwh13-' + [Guid]::NewGuid().ToString('N')
$volume = "$run-fixtures"
$result = Join-Path $project "test-artifacts/$run"
[IO.Directory]::CreateDirectory($result) | Out-Null

& $docker volume create --label hwh.demo=ticket13 $volume | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create fresh demo volume' }
try {
    $ErrorActionPreference = 'Continue'
    & $docker run --name $run --label hwh.demo=ticket13 --network none `
        --pids-limit 128 --memory 512m --cpus 2 --cap-drop ALL `
        --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID --cap-add CHOWN `
        --security-opt no-new-privileges `
        --mount "type=volume,source=$volume,target=/fixture-store" `
        --env "HWH_DEMO_RUN=$run" --entrypoint /bin/sh `
        $Image /src/tests/demo/run.sh 2>&1 |
        Tee-Object -FilePath (Join-Path $result 'demo.txt')
    $demoExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    & $docker cp "${run}:/results/." $result
    if ($LASTEXITCODE -ne 0) { throw "Result capture failed; demo exited $demoExit" }
    if ($demoExit -ne 0) { throw "Demo failed ($demoExit); see $result" }
    Write-Output "PASS: $result"
} finally {
    # Remove only resources uniquely created by this invocation.
    & $docker rm -f $run 2>&1 | Out-Null
    & $docker volume rm $volume 2>&1 | Out-Null
}
