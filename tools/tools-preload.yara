rule PRELOAD_0000_libprocesshider
{
	meta:
		description = "libprocesshider userland rootkit"
	strings:
		$ = "%d (%[^)]s"
		$ = "/proc/self/fd/%d"
		$ = "/proc/%s/stat"
		$ = "dlsym"
	condition:
		all of them
}

rule PRELOAD_0001_bdvl
{
	meta:
		description = "bdvl LD_PRELOAD rootkit"
	strings:
		$s1 = "Canadians are weird"
		$s2 = "ICMP backdoor up."
		$s3 = "It seems something may have went wrong installing..."
		$s4 = "Unable to evaluate total size of stolen stuff..."
		$s5 = "bdvlsuperreallygay"
		$s6 = "You're now totally visible. 'exit' when you want to return to being hidden."
	condition:
		uint32(0) == 0x464c457f
		and any of them
}
