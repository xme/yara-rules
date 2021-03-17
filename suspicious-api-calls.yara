rule process_hollowing
{
    strings:
        $1 = "CreateProcess" nocase wide ascii
        $2 = "UnmapViewOfSection" nocase wide ascii
	$3 = "VirtualAllocEx" nocase wide ascii
	$4 = "WriteProcessMemory" nocase wide ascii
	$5 = "ResumeThreat" nocase wide ascii
    condition:
	all of ($*)
}

rule process_enumeration
{
    strings:
        $1 = "CreateToolhelp32Snapshot" nocase wide ascii
        $2 = "Process32First" nocase wide ascii
	$3 = "Process32Next" nocase wide ascii
    condition:
	all of ($*)
}

rule api_address_search
{
    strings:
        $1 = "LoadLibrary" nocase wide ascii
        $2 = "GetProcAddress" nocase wide ascii
    condition:
	all of ($*)
}

rule dll_operations
{
    strings:
	$1 = "GetModuleHandle" nocase wide ascii
        $2 = "LoadLibrary" nocase wide ascii
        $3 = "GetProcAddress" nocase wide ascii
    condition:
        any of ($*)
}

rule suspicious_api
{
    strings:
	$1 = "FindWindow" nocase wide ascii
	$2 = "BlockInput" nocase wide ascii
	$3 = "VirtualAllocEx" nocase wide ascii
	$4 = "ProtectVirtualMemory" nocase wide ascii
	$5 = "RtlDecompressBuffer" nocase wide ascii
    condition:
	any of ($*)
}

rule windows_checks
{
    strings:
	$1 = "FindWindow" nocase wide ascii
	$2 = "GetWindowsText" nocase wide ascii
    condition:
	any of ($*)
}

rule api_hooking
{
    strings:
	$1 = "SetWindowsHookEx" nocase wide ascii
	$2 = "GetMessage" nocase wide ascii
	$3 = "CallNextHookEx" nocase wide ascii
    condition:
	all of ($*)
}

rule dropper_pe_resource
{
    strings:
	$1 = "FindResource" nocase wide ascii
	$2 = "SizeOfResource" nocase wide ascii
	$3 = "LockResource" nocase wide ascii
    condition:
	all of ($*)
}

rule clipboard_exfiltration
{
    strings:
	$1 = "OpenClipboard" nocase wide ascii
	$2 = "GetClipboardData" nocase wide ascii
	$3 = "CloseClipboard" nocase wide ascii
    condition:
	all of ($*)
}
