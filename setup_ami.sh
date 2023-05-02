#!/bin/bash

ami_key="keys/star_openlinksw_com.key.pem"
ami_cert="keys/star_openlinksw_com.crt.pem"

cp $ami_key cmd/indieauth-client/client.key
cp $ami_cert cmd/indieauth-client/client.crt
cp go.mod.ami go.mod
cp go.sum.ami go.sum

GOINSECURE=willnorris.com go get willnorris.com/go/webmention
# go get -x ./...
go get ./...
