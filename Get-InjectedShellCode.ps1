Import-Module .\Get-InjectedThread.ps1
Import-Module .\PowerShellArsenal\PowerShellArsenal.psd1 -Force
Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
    [In] System.IntPtr hProcess,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32


$log = Get-InjectedThread 
$log | ForEach-Object {
    $Proc = Get-Process -Id $_.ProcessId
    $is32Bit=[int]0
    foreach ($i in $_.Bytes.Length..1) {
        if([int]$_.Bytes[$i] -ne 0){
            $shellcode_length = $i
            break
        }
    }
    $Bytes = $_.Bytes[0..[Int32]$shellcode_length]
    if ([Kernel32.NativeMethods]::IsWow64Process($Proc.Handle, [ref]$is32Bit)) { 
        $OpCode = Get-CSDisassembly -Architecture X86 -Mode Mode32 -Code $Bytes -Offset $_.BaseAddress.ToInt64()
    }
    else{
        $OpCode = Get-CSDisassembly -Architecture X86 -Mode Mode64 -Code $Bytes -Offset $_.BaseAddress.ToInt64()
    }
    $_ | Add-Member -MemberType Noteproperty -Name OpCode -Value $OpCode
    $InjectedThread = $_
    $OtherShellCode = Get-ProcessMemoryInfo -ProcessID $_.ProcessId | Where-Object { $_.BaseAddress -ne $InjectedThread.BaseAddress} | Where-Object { 
            $_.Protect -eq "PAGE_EXECUTE_READWRITE" -and $_.AllocationProtect -eq "PAGE_EXECUTE_READWRITE" -and $_.Type -eq "MEM_PRIVATE" -and $_.State -eq "MEM_COMMIT"
        } | ForEach-Object {
            $bytes = ReadProcessMemory -BaseAddress $_.BaseAddress -Size $_.RegionSize -ProcessHandle $Proc.Handle;
            foreach ($i in $Bytes.Length..1) {
                if([int]$Bytes[$i] -ne 0){
                    $shellcode_length = $i
                    break
                }
            }
            $Bytes_Shell = $Bytes[0..[Int32]$shellcode_length]
            if ($is32Bit) { 
                $OpCode = Get-CSDisassembly -Architecture X86 -Mode Mode32 -Code $Bytes_Shell -Offset $_.BaseAddress
            }
            else{
                $OpCode = Get-CSDisassembly -Architecture X86 -Mode Mode64 -Code $Bytes_Shell -Offset $_.BaseAddress
            }
            $_ | Add-Member -MemberType Noteproperty -Name Bytes -Value $Bytes
            $_ | Add-Member -MemberType Noteproperty -Name OpCode -Value $OpCode
            $_
        } 
    Foreach ($i in 0..($OtherShellCode.Count-1)){
        $_ | Add-Member -MemberType Noteproperty -Name "ShellCode_$($i+1)" -Value $OtherShellCode[$i]
    }
    Write-Output $_
}

