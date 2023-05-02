#!/bin/bash

localhost_key="keys/localhost.client.key"
localhost_cert="keys/localhost.client.crt"

cp $localhost_key cmd/indieauth-client/client.key
cp $localhost_cert cmd/indieauth-client/client.crt
cp go.mod.localhost go.mod
cp go.sum.localhost go.sum

GOINSECURE=willnorris.com go get willnorris.com/go/webmention
# go get -x ./...
go get ./...
