#!/usr/bin/env bats

TEST_USERNAME=forremote

function setup() {
	source scripts/boxforming.sh
}

@test "Should be able to generate certificate" {
	run new_client_auth_cert $TEST_USERNAME
	[ -f $HOME/$TEST_USERNAME.crt.pem ]
	[ -f $HOME/$TEST_USERNAME.key.pem ]
	[ -f $HOME/$TEST_USERNAME.key.pub ]
}

@test "Should be able to parse certificate" {
	CERT_PATH=$HOME/$TEST_USERNAME.crt.pem
	run openssl asn1parse -in $CERT_PATH -strparse $(openssl asn1parse -in $CERT_PATH | grep -A 1 ':X509v3 Subject Alternative Name' | tail -n 1 | cut -d ':' -f 1)
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Microsoft Universal Principal Name" ]]
	[[ "$output" =~ "${TEST_USERNAME}@localhost" ]]
}

@test "Finalize" {
	# rm $HOME/$TEST_USERNAME.crt.pem
	rm $HOME/$TEST_USERNAME.key.pem
	rm $HOME/$TEST_USERNAME.key.pub

	skip
}
