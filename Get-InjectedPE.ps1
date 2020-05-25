Import-Module .\PowerShellArsenal\PowerShellArsenal.psd1 -Force
Import-Module .\Memory-Tools.ps1 -Force

function Get-HollowHunterReport {
    $PathCheck = (Test-Path .\hollows_hunter\hollows_hunter.exe) -and (Test-Path .\hollows_hunter\pe-sieve.dll)
    if (!$PathCheck) {
        Write-Error "Hollow Hunter not found!"
        Exit
    }
    $run = &"hollows_hunter\hollows_hunter.exe"
    Get-Content .\summary.json | ConvertFrom-Json 
}

function Get-MemoryInjection {
    Get-Process dZYayWzy | Where-Object {$_.Id} | ForEach-Object {   
        $ProcessID = $_.Id;
        Write-Host $_.Name;
        Get-ProcessMemoryInfo -ProcessID $_.Id | Where-Object { 
            $_.Protect -eq "PAGE_EXECUTE_READWRITE" -and $_.AllocationProtect -eq "PAGE_EXECUTE_READWRITE" -and $_.Type -eq "MEM_PRIVATE" -and $_.State -eq "MEM_COMMIT"
        } | ForEach-Object {
            $bytes = Dump-Memory -Address $_.BaseAddress -Offset $_.RegionSize -ProcessId $ProcessID;
            #$shellcode = Get-CSDisassembly -Architecture X86 -Mode Mode64 -Code $Bytes
            #$_ | Add-Member -MemberType Noteproperty -Name Bytes -Value $Bytes
            #$_ | Add-Member -MemberType Noteproperty -Name ShellCode -Value $shellcode
            $_
        } 
    }
}



#Get-HollowHunterReport
Get-MemoryInjection | ConvertTo-Json -Compress | Out-File a.json