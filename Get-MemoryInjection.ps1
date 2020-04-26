Import-Module .\PowerShellArsenal\PowerShellArsenal.psd1 -Force

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



$code = @"
    using System;
    using System.Runtime.InteropServices;
  
    public class PE
    {
        public enum IMAGE_DOS_SIGNATURE : ushort
        {
            DOS_SIGNATURE =                 0x5A4D,      // MZ
            OS2_SIGNATURE =                 0x454E,      // NE
            OS2_SIGNATURE_LE =              0x454C,      // LE
        }


        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct _IMAGE_DOS_HEADER
        {
            public IMAGE_DOS_SIGNATURE   e_magic;        // Magic number
            public ushort   e_cblp;                      // public bytes on last page of file
            public ushort   e_cp;                        // Pages in file
            public ushort   e_crlc;                      // Relocations
            public ushort   e_cparhdr;                   // Size of header in paragraphs
            public ushort   e_minalloc;                  // Minimum extra paragraphs needed
            public ushort   e_maxalloc;                  // Maximum extra paragraphs needed
            public ushort   e_ss;                        // Initial (relative) SS value
            public ushort   e_sp;                        // Initial SP value
            public ushort   e_csum;                      // Checksum
            public ushort   e_ip;                        // Initial IP value
            public ushort   e_cs;                        // Initial (relative) CS value
            public ushort   e_lfarlc;                    // File address of relocation table
            public ushort   e_ovno;                      // Overlay number
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string   e_res;                       // May contain 'Detours!'
            public ushort   e_oemid;                     // OEM identifier (for e_oeminfo)
            public ushort   e_oeminfo;                   // OEM information; e_oemid specific
            [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=10)]
            public ushort[] e_res2;                      // Reserved public ushorts
            public int      e_lfanew;                    // File address of new exe header
        }
    }
"@

Add-Type -TypeDefinition $code -WarningAction SilentlyContinue | Out-Null

#Get-Process | ForEach-Object { Get-StructFromMemory -Id $_.Id -MemoryAddress $_.MainModule.BaseAddress -StructType ([PE+_IMAGE_DOS_HEADER]) }



Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
    [In] System.IntPtr hProcess,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32

Get-MemoryInjection
