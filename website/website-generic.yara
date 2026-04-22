rule WEBSITE_0001_ngrok_url
{
	meta:
		description = "Contains ngrok.io string"
	strings:
		$ = ".ngrok.io" ascii wide
	condition:
		all of them
}

rule WEBSITE_0002_dropbox_url
{
	meta:
		description = "Contains a DropBox URL"
	strings:
		$ = "https://dl.dropbox.com/" ascii wide
	condition:
		all of them
}

rule WEBSITE_0003_dropbox
{
	meta:
		description = "Contains dropbox.com"
	strings:
		$ = "dropbox.com" ascii wide
	condition:
		all of them
}
