rule KEYS_0000_private_key
{
	meta:
		description = "Private key"
	strings:
		$ = "BEGIN PRIVATE KEY" ascii wide
	condition:
		all of them
}

rule KEYS_0001_private_rsa_key
{
	meta:
		description = "RSA private key"
	strings:
		$ = "BEGIN RSA PRIVATE KEY" ascii wide
	condition:
		all of them
}

rule KEYS_0002_openssh_private_key
{
	meta:
		description = "OpenSSH private key"
	strings:
		$ = "BEGIN OPENSSH PRIVATE KEY"
	condition:
		all of them
}
