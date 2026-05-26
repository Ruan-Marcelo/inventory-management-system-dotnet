$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$jobs = @()

function Stop-AuthJobs {
    foreach ($job in $jobs) {
        if ($job.State -eq "Running") {
            Stop-Job $job | Out-Null
        }
        Remove-Job $job -Force | Out-Null
    }
}

try {
    $jobs += Start-Job -Name "AuthAPI" -ScriptBlock {
        param($root)
        Set-Location $root
        dotnet run --project AuthAPI/AuthAPI.csproj --launch-profile https
    } -ArgumentList $root

    $jobs += Start-Job -Name "AuthUI" -ScriptBlock {
        param($root)
        Set-Location $root
        dotnet run --project AuthUI/AuthUI.csproj --launch-profile https
    } -ArgumentList $root

    Write-Host "AuthAPI: https://localhost:7004"
    Write-Host "AuthUI : https://localhost:7151"
    Write-Host "Pressione Ctrl+C para parar os dois."
    Write-Host ""

    while ($true) {
        foreach ($job in $jobs) {
            Receive-Job $job
        }

        $finished = $jobs | Where-Object { $_.State -in @("Completed", "Failed", "Stopped") }
        if ($finished.Count -gt 0) {
            foreach ($job in $finished) {
                Write-Host ""
                Write-Host "$($job.Name) terminou com estado: $($job.State)"
                Receive-Job $job
            }
            break
        }

        Start-Sleep -Seconds 1
    }
}
finally {
    Stop-AuthJobs
}
