Import-Module .\PowerShellArsenal\PowerShellArsenal.psd1 -Force
Import-Module .\Get-InjectedThread.ps1


$hashtable = @{};
$signtable = @{};

function Get-Signature {
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath
    )
    if (Test-Path -Path $FilePath -PathType Leaf ){
        if ($signtable.get_item($FilePath)){
            Return $signtable.get_item($FilePath)
        }
        else {
            $sign = Get-AuthenticodeSignature -FilePath $FilePath
            if ($sign.Status -eq "Valid") {
                $dnDict = ($sign.SignerCertificate.Subject -split ', ') | ForEach-Object {
                    $dnDict = @{}
                    $item = $_.Split('='); $dnDict[$item[0]] = $item[1]
                    $dnDict
                }
                $s = "(Verified) $($dnDict."O")"
                $signtable.Add($FilePath, $s)
                Return $s
            }
        }
    }
}

function Get-FileHash {
    Param(
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath,
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
        [string]$HashType = "MD5"
    )
        
        switch ( $HashType.ToUpper() )
        {
            "MD5"       { $hash = [System.Security.Cryptography.MD5]::Create() }
            "SHA1"      { $hash = [System.Security.Cryptography.SHA1]::Create() }
            "SHA256"    { $hash = [System.Security.Cryptography.SHA256]::Create() }
            "SHA384"    { $hash = [System.Security.Cryptography.SHA384]::Create() }
            "SHA512"    { $hash = [System.Security.Cryptography.SHA512]::Create() }
            "RIPEMD160" { $hash = [System.Security.Cryptography.RIPEMD160]::Create() }
            default     { "Invalid hash type selected." }
        }

        if ($hashtable.get_item($FilePath)) {
            $PaddedHex = $hashtable.get_item($FilePath)
            $PaddedHex
        } else {
            if (Test-Path $FilePath) {
                $File = Get-ChildItem -Force $FilePath
                $fileData = [System.IO.File]::ReadAllBytes($File.FullName)
                $HashBytes = $hash.ComputeHash($fileData)
                $PaddedHex = ""
        
                foreach($Byte in $HashBytes) {
                    $ByteInHex = [String]::Format("{0:X}", $Byte)
                    $PaddedHex += $ByteInHex.PadLeft(2,"0")
                }
                $hashtable.Add($FilePath, $PaddedHex)
                $PaddedHex
                
            } else {
                "${FilePath} is locked or could not be not found."
                Write-Error -Category InvalidArgument -Message ("{0} is locked or could not be found." -f $FilePath)
            }
    }
}

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

    $AllModule = (Get-Process | Select-Object Id, Path, Modules | ForEach-Object{ 
        $ProcessID = $_.Id
        $Path = $_.Path
        $_.Modules | ForEach-Object {
            $_ | Add-Member NoteProperty PID $ProcessID -Force
            $_ | Add-Member NoteProperty Path $Path -Force
            $_
        } 
    } | Group-Object -Property FileName | Where-Object {$_.Count -eq 1} | Select-Object Group ).Group | Where-Object {(Split-Path $_.Path -Parent) -eq "C:\Windows\System32" -or (Split-Path $_.Path -Parent) -eq "C:\Windows\SysWOW64"}

    $AllModule | ForEach-Object{ 
        $Module = $_
        $Proc = Get-Process -Id $_.PID
        $ImportOfModule = (Get-PE -ProcessId $Proc.Id -ModuleBaseAddress $Module.BaseAddress).Imports.ModuleName
        If(!($ImportOfModule | Where-Object {!(Test-path -Path "C:\Windows\System32\$($_)") })){
            $ImportOfMain = (Get-PE -ProcessId $Proc.Id -ModuleBaseAddress $Proc.MainModule.BaseAddress).Imports.ModuleName
            If($ImportOfMain -notcontains $_.ModuleName -and $_.Filename -ne $Proc.MainModule.Filename){
                $i=0;
                $Proc.Modules.Modulename | ForEach-Object{
                    $i = $i + 1
                    If($ImportOfMain -notcontains $_){
                        $i = $i - 1
                    }
                }
                If($Proc.Modules.Filename[$i..$Proc.Modules.Count] -contains $Module.Filename){
                    $Path = $Proc.Modules.Filename | Foreach-Object { Split-Path $_ -Parent } | Group-Object
                    $ModulePath = Split-Path $Module.Filename -Parent
                    If($Path | Where-Object {$_.Count -eq 1 -and $_.Name -eq $ModulePath}){
                        Write-host "DLL Injection: "+ $Module.Path
                        Write-host "DLL Injection: "+ $Module.Filename
                    }
                }            
            }
        }
    }

    # $Module = Get-Process | ForEach-Object{
    #     $Proc = $_;
    #     #$AllModule = ($Proc.Modules.BaseAddress | ForEach-Object { Get-PE -ProcessId $Proc.Id -ModuleBaseAddress $_}).Imports.ModuleName | Sort-Object -Unique
    #     $AllModule = (Get-PE -ProcessId $Proc.Id -ModuleBaseAddress $Proc.MainModule.BaseAddress).Imports.ModuleName
    #     $ProcModule = $Proc.Modules.ModuleName
    #     $MalModule = (Compare-Object -ReferenceObject $ProcModule -DifferenceObject $AllModule -IncludeEqual | Where-Object {$_.SideIndicator -eq "<="}).InputObject
    #     $MalModule = $MalModule | ForEach-Object{
    #         $Name = $_
    #         $Proc.Modules | Where-Object { $_ -ne $Proc.MainModule -and $_.ModuleName -eq $Name}
    #     }
    #     Write-Host $Proc.Id
    #     $MalModule
    #     # 
    #     # Write-Host $Proc.Id
    #     # $PeFile = Get-PE -ProcessId $Proc.Id -ModuleBaseAddress $Proc.MainModule.BaseAddress;
    #     # if ($PeFile) {
    #     #     $OtherDll = Compare-Object -ReferenceObject $Proc.Modules.ModuleName -DifferenceObject $PeFile.ImportDirectory.Name -PassThru;
    #     #     Write-Host $OtherDlls
    #     #     $Proc.Modules | Where-Object { $_ -ne $Proc.MainModule -and $_.Company -ne "Microsoft Corporation"} | ForEach-Object{
    #     #         foreach($dll in $OtherDll){
    #     #             if($dll -eq $_.ModuleName){
    #     #                 $sign = Get-Signature $_.FileName
    #     #                 Write-Host $_.FileName
    #     #                 Write-Host ($sign -notmatch "(Verified)")
    #     #                 if ($sign -notmatch "(Verified)"){
    #     #                     $hash = Get-FileHash $_.FileName
    #     #                     Write-Host $_.FileName
    #     #                     Write-Host $sign
    #     #                     Write-Host $hash
    #     #                 }
    #     #             }
    #     #         }
    #     #     }
    #     # }
    # }
    # $module | Group-Object -Property FileName -NoElement 
}

Get-DllInjection


