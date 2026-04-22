rule TOOLS_0000_nmap
{
	meta:
		description = "Nmap network scanner"
		reference = "https://nmap.org"
    strings:
        $ = "Usage: nmap [Scan Type(s)] [Options] {target specification}"
    condition:
        all of them
}

rule TOOLS_0001_MD5_constants
{
    meta:
        author = "Daniel Roberson"
        description = "MD5 constants"
    strings:
        $c1 = { 01234567 }
        $c2 = { 89abcdef }
        $c3 = { fedcba98 }
        $c4 = { 76543210 }

        $r1 = { 78a46ad7 }
        $r2 = { 56b7c7e8 }
        $r3 = { db702024 }
        $r4 = { eecebdc1 }
        $r5 = { af0f7cf5 }
        $r6 = { 2ac68747 }
        $r7 = { 134630a8 }
        $r8 = { 019546fd }
        $r9 = { d8988069 }
        $r10 = { aff7448b }
        $r11 = { b15bffff }
        $r12 = { bed75c89 }
        $r13 = { 2211906b }
        $r14 = { 937198fd }
        $r15 = { 8e4379a6 }
        $r16 = { 2108b449 }
        $r17 = { 62251ef6 }
        $r18 = { 40b340c0 }
        $r19 = { 515a5e26 }
        $r20 = { aac7b6e9 }
        $r21 = { 5d102fd6 }
        $r22 = { 53144402 }
        $r23 = { 81e6a1d8 }
        $r24 = { c8fbd3e7 }
        $r25 = { e6cde121 }
        $r26 = { d60737c3 }
        $r27 = { 870dd5f4 }
        $r28 = { ed145a45 }
        $r29 = { 05e9e3a9 }
        $r30 = { f8a3effc }
        $r31 = { d9026f67 }
        $r32 = { 8a4c2a8d }
        $r33 = { 4239faff }
        $r34 = { 81f67187 }
        $r35 = { 22619d6d }
        $r36 = { 0c38e5fd }
        $r37 = { 44eabea4 }
        $r38 = { a9cfde4b }
        $r39 = { 604bbbf6 }
        $r40 = { 70bcbfbe }
        $r41 = { c67e9b28 }
        $r42 = { fa27a1ea }
        $r43 = { 8530efd4 }
        $r44 = { 051d8804 }
        $r45 = { 39d0d4d9 }
        $r46 = { e599dbe6 }
        $r47 = { f87ca21f }
        $r48 = { 6556acc4 }
        $r49 = { 442229f4 }
        $r50 = { 97ff2a43 }
        $r51 = { a72394ab }
        $r52 = { 39a093fc }
        $r53 = { c3595b65 }
        $r54 = { 92cc0c8f }
        $r55 = { 7df4efff }
        $r56 = { d15d8485 }
        $r57 = { 4f7ea86f }
        $r58 = { e0e62cfe }
        $r59 = { 144301a3 }
        /*
        ClamAV complained about having more than 64 strings...
        $r60 = { a111084e }
        $r61 = { 827e53f7 }
        $r62 = { 35f23abd }
        $r63 = { bbd2d72a }
        $r64 = { 91d386eb }
        */
    condition:
        all of them
}

rule TOOLS_0002_SHA256_constants
{
    meta:
        description = "SHA256 constants"
    strings:
        $ = { 852c7292 }
        $ = { a1e8bfa2 }
        $ = { 4b661aa8 }
        $ = { 708b4bc2 }
        $ = { a3516cc7 }
        $ = { 19e892d1 }
        $ = { 240699d6 }
        $ = { 85350ef4 }
        $ = { 70a06a10 }
        $ = { 16c1a419 }
        $ = { 086c371e }
        $ = { 4c774827 }
        $ = { b5bcb034 }
        $ = { b30c1c39 }
        $ = { 4aaad84e }
        $ = { 4fca9c5b }
        $ = { f36f2e68 }
        $ = { ee828f74 }
        $ = { 6f63a578 }
        $ = { 1478c884 }
        $ = { 0802c78c }
        $ = { faffbe90 }
        $ = { eb6c50a4 }
        $ = { f7a3f9be }
        $ = { f27871c6 }
    condition:
        all of them
}

rule TOOLS_0003_crypto_constants_crc32
{
    meta:
        author = "Daniel Roberson"
        description = "crc32 constants"
    strings:
        $r4 = { 96300777 }
        $r5 = { 2c610eee }
        $r6 = { ba510999 }
        $r7 = { 19c46d07 }
        $r8 = { 8ff46a70 }
/*$r9 = { 35a563e9 }
$r10 = { a395649e }
$r11 = { 3288db0e }
$r12 = { a4b8dc79 }
$r13 = { 1ee9d5e0 }
$r14 = { 88d9d297 }
$r15 = { 2b4cb609 }
$r16 = { bd7cb17e }
$r17 = { 072db8e7 }
$r18 = { 911dbf90 }
$r19 = { 6410b71d }
$r20 = { f220b06a }
$r21 = { 4871b9f3 }
$r22 = { de41be84 }
$r23 = { 7dd4da1a }
$r24 = { ebe4dd6d }
$r25 = { 51b5d4f4 }
$r26 = { c785d383 }
$r27 = { 56986c13 }
*/
    condition:
        all of them
}

rule TOOLS_0004_rc4_ksa
{
    meta:
        author = "Thomas Barabosch"
        description = "Searches potential setup loops of RC4's KSA"
    strings:
        $s0 = { 3d 00 01 00 00 }       // cmp eax, 256
        $s1 = { 81 f? 00 01 00 00 }    // cmp {ebx, ecx, edx}, 256
        $s2 = { 48 3d 00 01 00 00 }    // cmp rax, 256
        $s3 = { 48 81 f? 00 01 00 00 } // cmp {rbx, rcx, ...}, 256
    condition:
        any of them
}

rule TOOLS_0005_base64_alphabet
{
    meta:
        description = "Base64 alphabet"

    strings:
        $ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii wide

    condition:
        all of them
}

rule TOOLS_0006_salsa20_constants
{
    meta:
        description = "Salsa20 stream cipher constants. Used by various ransomware"
        reference = "https://github.com/alexwebr/salsa20/blob/master/salsa20.c#L118-L125"
    strings:
        $ = "expand 32-byte k"
    condition:
        all of them
}

rule TOOLS_0007_murmurhash_constants
{
    meta:
        author = "Daniel Roberson"
        description = "mmh3 constants"
    strings:
        $c1 = { 512d9ecc }
        $c2 = { 9335871b }
        $c3 = { 646b54e6 }
        $c4 = { 35aeb2c2 }
    condition:
        all of them
}

rule TOOLS_0008_sockets
{
    meta:
        description = "Berkeley Sockets API"
        reference = "https://en.wikipedia.org/wiki/Berkeley_sockets"
        author = "Daniel Roberson"
    strings:
        $socket = "socket" fullword
        $ = "accept" fullword
        $ = "bind" fullword
        $ = "getsockname" fullword
        $ = "listen" fullword
        $ = "close" fullword
    condition:
        $socket and 2 of them
}

rule TOOLS_0009_winsock
{
    meta:
        description = "Utilizes Winsock"
        reference = "https://docs.microsoft.com/en-us/windows/win32/winsock/initializing-winsock"
    strings:
        $ = "WSAStartup" ascii wide
        $ = "ws2_32.dll" ascii wide nocase
    condition:
        any of them
}

rule TOOLS_0010_shc
{
    meta:
        description = "Compiled with generic shell script compiler (shc)"
        reference = "https://github.com/neurobin/shc"
        decompiler = "https://github.com/yanncam/UnSHc"
    strings:
        $ = "=%lu %d"
        $ = "%lu %d%c"
        $ = "%s%s%s: %s"
    condition:
        uint32(0) == 0x464c457f and all of them
}

rule TOOLS_0011_gscript
{
	meta:
		description = "https://github.com/gen0cide/gscript"
	strings:
		$ = "github.com/gen0cide/gscript"
	condition:
		any of them
}

rule TOOLS_0012_autoit3
{
	meta:
		description = "AutoIt 3"
		reference = "https://www.autoitscript.com/site/"
		decompiler = "http://domoticx.com/autoit3-decompiler-exe2aut/"
	strings:
		$ = "AutoIt v3" wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule TOOLS_0013_socat
{
    meta:
        description = "socat multipurpose relay"
        reference = "http://www.dest-unreach.org/socat/"
    strings:
        $ = "socat version %s on %s"
    condition:
        all of them
}

rule TOOLS_0014_loki2
{
    meta:
        description = "http://phrack.org/issues/51/6.html"
    strings:
        $a = "lokid: inactive client <%d> expired from list [%d]"
        $b = "[SUPER fatal] control should NEVER fall here"
    condition:
        any of them
}

rule TOOLS_0015_pyinstaller
{
    meta:
        description = "https://www.pyinstaller.org/"
    strings:
        $a = "_MEIPASS"
    condition:
        all of them
}

rule TOOLS_0016_tinymet
{
    meta:
        description = "https://github.com/SherifEldeeb/TinyMet"
    strings:
        $a = "tinymet.com"
        $b = "TinyMet"
        $c = "Available transports are as follows:"
    condition:
        all of them
}

rule TOOLS_0017_nanomet
{
    meta:
        description = "https://github.com/kost/nanomet"
    strings:
        $a = "github.com/kost/nanomet"
        $b = "nanomet.exe"
        $c = "Available transports are as follows:"
    condition:
        all of them
}

rule TOOLS_0018_prism
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/andreafabrizi/prism"
	strings:
		$a = "PRISM"
		$b = "I'm not root :("
	condition:
		all of them
}

rule TOOLS_0019_masscan
{
	meta:
		description = "https://github.com/robertdavidgraham/masscan"
	strings:
		$a = " masscan -"
		$b = "https://github.com/robertdavidgraham/masscan"
	condition:
		any of them
}

rule TOOLS_0020_ptrace
{
	meta:
		description = "ELF files possibly abusing ptrace"
	strings:
		$ = "ptrace"
	condition:
		uint32(0) == 0x464c457f and all of them
}
