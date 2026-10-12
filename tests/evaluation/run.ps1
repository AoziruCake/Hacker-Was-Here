param(
    [string]$Image = 'hwh-safefs-lab:ticket11'
)
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$docker = (Get-Command docker -ErrorAction Stop).Source
$run = 'hwh11-' + [Guid]::NewGuid().ToString('N')
$volume = "$run-fixtures"
$result = Join-Path $project "test-artifacts/$run"
[IO.Directory]::CreateDirectory($result) | Out-Null
& $docker volume create --label hwh.evaluation=ticket11 $volume
if ($LASTEXITCODE -ne 0) { throw 'Could not create fresh evaluation volume' }
try {
    $ErrorActionPreference = 'Continue'
    & $docker run --name $run --label hwh.evaluation=ticket11 --network none `
        --pids-limit 128 --memory 512m --cpus 2 --cap-drop ALL `
        --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP `
        --cap-add CHOWN --security-opt no-new-privileges `
        --mount "type=volume,source=$volume,target=/fixture-store" `
        --env "HWH_TEST_RUN=$run" --entrypoint /bin/sh $Image `
        /src/tests/evaluation/run.sh 2>&1 |
        Tee-Object -FilePath (Join-Path $result 'evaluation.txt')
    $testExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    & $docker cp "${run}:/results/." $result
    if ($LASTEXITCODE -ne 0) { throw "Result capture failed; evaluation exited $testExit" }
    if ($testExit -ne 0) { throw "Evaluation failed ($testExit); see $result" }
    Write-Output "PASS: $result"
} finally {
    & $docker rm -f $run
    & $docker volume rm $volume
}
