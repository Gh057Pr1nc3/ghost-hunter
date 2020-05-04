Import-Module .\PowerShellArsenal\PowerShellArsenal.psd1 -Force
Import-Module .\Get-InjectedThread.ps1

function Get-MemoryInjection {
    Get-Process | ForEach-Object {   
        $ProcessID = $_.Id;
        Write-Host $_.Name;
        Get-ProcessMemoryInfo -ProcessID $_.Id | Where-Object { 
            $_.Protect -eq "PAGE_EXECUTE_READWRITE" -and $_.AllocationProtect -eq "PAGE_EXECUTE_READWRITE" -and $_.Type -eq "MEM_PRIVATE" 
        } | ForEach-Object {
            $bytes = Get-RawMemory -Address $_.BaseAddress -Offset $_.RegionSize -ProcessId $ProcessID;
            if (Compare-Object -ReferenceObject $bytes[1..3] -DifferenceObject @(0, 0, 0) -PassThru) {
                $_
            }
        } | ForEach-Object {
            $_ | Add-Member NoteProperty ProcessID $ProcessID -Force
            $_ | Add-Member NoteProperty ShellCode $bytes -Force
            $_
        }
    }
}

#Get-MemoryInjection

function Get-DllInjection{
    Get-Process | ForEach-Object{
        Get-PEB $_.ID | Where-Object {$_.ProcessAttachCalled -eq $false}
    }
}


