rule ELF_0000_File_Header
{
    meta:
        description = "ELF file '\x7fELF' header as string"
        author = "Daniel Roberson"
    strings:
        $elf = "\x7fELF"
    condition:
        $elf at 0
}
