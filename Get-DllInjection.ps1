Import-Module .\PowerShellArsenal\PowerShellArsenal.psd1 -Force


Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
    [In] System.IntPtr hProcess,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32

$AllInMemoryOrderModuleList = @()

$DllModule = Get-Process | Where-Object {$_ -ne $null -and $_.Path.StartsWith("C:\Windows\") -and $_.Id -ne $PID} | ForEach-Object {
    Write-Host $_.Id 
    Write-Host $_.Name
    $Process = $_
    $is32Bit=[int]0 
    $a = [Kernel32.NativeMethods]::IsWow64Process($_.Handle, [ref]$is32Bit)
    if($is32Bit){
        $InMemoryOrderModuleList = &"$env:windir\SysWow64\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "(Get-PEB -Id $($_.Id)).InMemoryOrderModuleList | ConvertTo-CSV" | ConvertFrom-Csv
		
    }
    else {
        $InMemoryOrderModuleList = (Get-PEB -Id $_.Id).InMemoryOrderModuleList
    }
	$AllInMemoryOrderModuleList += $InMemoryOrderModuleList
    $InMemoryOrderModuleList | Where-Object {
	$_.ProcessAttachCalled -eq $false -and $_.BaseDllName -ne "ntdll.dll" -and $_.FullDllName -ne $Process.MainModule.FileName
	} | Select-Object BaseAddress, SizeOfImage, FullDllName, BaseDllName | ForEach-Object{
		$_ | Add-Member NoteProperty ProcessName $Process.ProcessName -Force
		$_ | Add-Member NoteProperty ProcessID $Process.Id -Force
		$_ | Add-Member NoteProperty ProcessPath $Process.Path -Force
		$_
	}
}
$AllModule = ($AllInMemoryOrderModuleList | Select-Object FullDllName | Group-Object FullDllName | Where-Object { $_.Count -eq 1 }).Values
$DllModule | Where-Object { $_.FullDllName -in $AllModule}