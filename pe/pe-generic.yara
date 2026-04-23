import "pe"

rule PE_0000_File_Header
{
    meta:
        description = "PE file 'MZ' header as string"
        author = "Daniel Roberson"
    strings:
        $pe = "MZ"
    condition:
        $pe at 0
}

rule PE_0001_ppid_spoofing
{
    meta:
        author = "Daniel Roberson"
        description = "Contains imports necessary to implement Parent Process ID (PPID) spoofing"
    condition:
        uint16(0) == 0x5a4d and
        pe.imports("kernel32.dll", "InitializeProcThreadAttributeList") and
        pe.imports("kernel32.dll", "OpenProcess") and
        pe.imports("kernel32.dll", "DuplicateHandle") and
        pe.imports("kernel32.dll", "UpdateProcThreadAttribute") and (pe.imports("kernel32.dll", "CreateProcessA") or pe.imports("kernel32.dll", "CreateProcessW"))
}

rule PE_0002_ppid_spoofing_broad
{
    meta:
        description = "Contains imports necessary to implement Parent Process ID (PPID) spoofing"
    strings:
        $ = "InitializeProcThreadAttributeList" wide ascii
        $ = "OpenProcess" wide ascii
        $ = "DuplicateHandle" wide ascii
        $ = "UpdateProcThreadAttribute" wide ascii
        $ = "CreateProcess" wide ascii
    condition:
      all of them
}

rule PE_0003_runkeys
{
    meta:
        description = "run key strings"
    strings:
        $ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii nocase
    condition:
        any of them
}

rule PE_0004_contains_pdb_path
{
    meta:
        description = "PE file containing PDB path"
        prereq = "Requires yara v4.0.0+"
    condition:
        pe.pdb_path
}

