param([string]$Image = 'hwh-safefs-lab:ticket14')
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$docker = (Get-Command docker -ErrorAction Stop).Source
$git = (Get-Command git -ErrorAction Stop).Source
$run = 'hwh14-' + [Guid]::NewGuid().ToString('N')
$vuln = "$run-vuln"
$volume = "$run-fixtures"
$result = Join-Path $project "test-artifacts/$run"
$govuln = Join-Path $result 'govulncheck.txt'
[IO.Directory]::CreateDirectory($result) | Out-Null

$commit = (& $git -C $project rev-parse HEAD).Trim()
if ($commit -notmatch '^[0-9a-fA-F]{40}$') { throw "Unexpected source commit: $commit" }
$dirty = if ((& $git -C $project status --porcelain) | Where-Object { $_ }) { 'true' } else { 'false' }

& $docker volume create --label hwh.release=ticket14 $volume | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create fresh release volume' }
try {
    $ErrorActionPreference = 'Continue'
    & $docker run --name $vuln --label hwh.release=ticket14 `
        --pids-limit 128 --memory 512m --cpus 2 --cap-drop ALL `
        --security-opt no-new-privileges --entrypoint /bin/sh `
        $Image /src/tests/release/govulncheck.sh 2>&1 |
        Tee-Object -FilePath (Join-Path $result 'govulncheck-run.txt')
    $vulnExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    & $docker cp "${vuln}:/results/govulncheck.txt" $govuln
    if ($LASTEXITCODE -ne 0) { throw "govulncheck capture failed; exited $vulnExit" }
    if ($vulnExit -ne 0) { throw "govulncheck failed ($vulnExit); see $result" }

    $ErrorActionPreference = 'Continue'
    & $docker run --name $run --label hwh.release=ticket14 --network none `
        --pids-limit 128 --memory 512m --cpus 2 --cap-drop ALL `
        --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID --cap-add CHOWN `
        --security-opt no-new-privileges `
        --mount "type=volume,source=$volume,target=/fixture-store" `
        --mount "type=bind,source=$govuln,target=/govulncheck.txt,readonly" `
        --env "HWH_RELEASE_RUN=$run" `
        --env "HWH_SOURCE_COMMIT=$commit" `
        --env "HWH_SOURCE_DIRTY=$dirty" `
        --entrypoint /bin/sh `
        $Image /src/tests/release/run.sh 2>&1 |
        Tee-Object -FilePath (Join-Path $result 'release.txt')
    $releaseExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    & $docker cp "${run}:/results/." $result
    if ($LASTEXITCODE -ne 0) { throw "Result capture failed; release exited $releaseExit" }
    if ($releaseExit -ne 0) { throw "Release candidate failed ($releaseExit); see $result" }
    Write-Output "PASS: $result"
} finally {
    & $docker rm -f $run 2>&1 | Out-Null
    & $docker rm -f $vuln 2>&1 | Out-Null
    & $docker volume rm $volume 2>&1 | Out-Null
}
