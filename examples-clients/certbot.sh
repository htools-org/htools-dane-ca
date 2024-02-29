#!/bin/sh

sudo certbot certonly \
	--standalone \
	--server https://localhost:8443/directory `#URL of your ACMEByProxy server` \
	--pre-hook 'rm -rf /etc/letsencrypt/accounts' `#certbot tries to reuse account keys, but we don't store them` \
	--force-renewal \
	--agree-tos \
	--no-eff-email \
	--reuse-key \
	-vv \
	-m 'me+noemail@localhost' \
	-d letsdane \
	--no-verify-ssl # XXX: very bad, no good idea!
