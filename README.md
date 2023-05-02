# IndieAuth Test Client

A Go IndieAuth client used for testing the [IndieAuth](https://indieauth.spec.indieweb.org/) server included as part of Virtuoso Authentication Layer ([VAL](https://vos.openlinksw.com/owiki/wiki/VOS/ValWhatWhyHow)).

This project is based on the Go IndieAuth client and server libraries provided by <https://github.com/hacdias/indieauth>. The client library has been extended into an https server. The server library has been removed as it isn't required.

The test client can be run on localhost, or on an AMI. As a pre-requisite, you need a working Go installation and a server X.509 key and certificate pair, each stored in a separate PEM file.

Copy your key and certificate to `./keys/` and edit either `setup_ami.sh` or `setup_localhost.sh` to correctly identify these files.

Run one of the above setup scripts as appropriate. e.g.

```
ssh cblakeley@osdb.openlinksw.com
cd ~/go/indieauth
cp {some_dir}/star_openlinksw_com.crt.pem  ./keys
cp {some_dir}/star_openlinksw_com.key.pem ./keys
./setup_ami.sh
```

If you encounter an error with the `webmention` library (which hasn't been published correctly), try:

```
GOINSECURE=willnorris.com go get willnorris.com/go/webmention
```

Update `./client/login-form.html:63` to provide a suitable default value for 'Personal URL'.

Once the application has been set up, run it as follows:   
(Root permissions aren't needed to run the IndieAuth client https server.)

Either:

```
cd ~/go/indieauth
screen -S indieauth_client
./run_client.ami
Ctrl-A-D
```

or, for a localhost instance, simply:

```
cd ~/go/indieauth
./run_client.localhost
```

## Restrictions

The IndieAuth Test Client currently only supports one browser client. It uses a global variable gClient to store the browser client's authentication data and session ID. Multiple browsers using this IndieAuth client will compete for and overwrite this single global var. To support multiple browser clients, gClient needs replacing by a map, or similar, keyed on session ID.
