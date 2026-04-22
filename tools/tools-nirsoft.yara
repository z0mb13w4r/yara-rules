rule NIRSOFT_00000_generic
{
	meta:
		description = "Generic catch-all for NirSoft tools"
	strings:
		$ = "NirSoft" ascii wide
	condition:
		all of them
}

rule NIRSOFT_0001_lsasecretsview
{
	meta:
		description = "NirSoft LSA Secrets View"
		reference = "https://www.nirsoft.net/utils/lsa_secrets_view.html"
	strings:
		$ = "NirSoft" wide
		$ = "LSA Secrets Viewer" wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule NIRSOFT_0002_mailpassview
{
	meta:
		description = "NirSoft MailPassView"
		reference = "https://www.nirsoft.net/utils/mailpv.html"
	strings:
		$ = "IncrediMail" wide
		$ = "NirSoft" wide
		$ = "PassView" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1MB and all of them
}
