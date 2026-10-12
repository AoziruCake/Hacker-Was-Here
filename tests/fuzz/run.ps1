param(
    [string]$Image = 'hwh-safefs-lab:ticket12',
    [string]$FuzzTime = '30s'
)

$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$docker = (Get-Command docker -ErrorAction Stop).Source
$run = 'hwh12-fuzz-' + [Guid]::NewGuid().ToString('N')
$result = Join-Path $project "test-artifacts/$run"
[IO.Directory]::CreateDirectory($result) | Out-Null

try {
    & $docker run --name $run --label hwh.validation.lab=ticket12 `
        --network none --pids-limit 128 --memory 512m --cpus 2 `
        --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP --cap-add CHOWN `
        --security-opt no-new-privileges `
        --env "HWH_FUZZ_TIME=$FuzzTime" `
        --entrypoint /bin/sh $Image /src/tests/fuzz/run.sh 2>&1 |
        Tee-Object -FilePath (Join-Path $result 'fuzz.txt')
    $testExit = $LASTEXITCODE
    if ($testExit -ne 0) {
        throw "Fuzz tests failed ($testExit); see $result"
    }
    Write-Output "PASS: $result"
} finally {
    & $docker rm -f $run 2>$null
}
