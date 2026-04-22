rule GOLANG_0000_build
{
    meta:
        description = "Golang"
    strings:
        $s1 = "Go build"
        $s2 = "go.build"
        $go = "/go-"
    condition:
        any of ($s*) or #go > 10
}

rule GOLANG_0001_ssh
{
	meta:
		description = "Golang binary including golang.org/x/crypto/ssh"
		reference = "https://pkg.go.dev/golang.org/x/crypto/ssh"
	strings:
		$ = "golang.org/x/crypto/ssh"
	condition:
		all of them
}

rule GOLANG_0002_protobuf
{
	meta:
		description = "Golang binary with Google protobuf package"
	strings:
		$ = "google.golang.org/protobuf"
	condition:
		all of them
}
