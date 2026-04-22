rule PE_000_File_Header
{
    meta:
        description = "PE file 'MZ' header as string"
        author = "Daniel Roberson"
    strings:
        $pe = "MZ"
    condition:
        $pe at 0
}
