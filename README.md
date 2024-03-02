# Handshake Tools DANE CA

**Live:** https://acme.htools.work/

This is a fork of [dvtirol/serles-acme](https://github.com/dvtirol/serles-acme), modified to issue certificates for use with DANE (on [Handshake](https://handshake.org) domains).

## Features

- Use with any ACME client ([certbot](https://certbot.eff.org/), etc.)
- Generate certificates for Handshake domains
- New CA keys are generated (and destroyed) while signing every certificate

### Customization options

Requests are flexible and options are passed by appending keywords to the email address:

- `+email` - opt into receiving emails with TLSA records after every cert issue.
- `+nohip17` - opt out of HIP-17 (Stateless DANE) extensions
- `+longttl` - request for long-lived certificates (1 year) - only applies if no HIP-17

Options can be combined. Example:

- `myvalidaddress+email+longttl+nohip17@gmail.com` - get emails and long-lived certs without HIP-17 extensions

## Usage

Use an ACME client like you would for any regular website, along with a new arg `--server`:

```sh
sudo certbot --nginx -d your_tld.or_sld --server https://acme.htools.work/directory --reuse-key
```

## Documentation

Check out the original project this is forked from: [dvtirol/serles-acme](https://github.com/dvtirol/serles-acme)

## Run Locally

Clone the project:

```sh
git clone https://github.com/htools-org/htools-dane-ca
cd htools-dane-ca
```

Set up a virtual env with `venv` or `pyenv` and activate it.

Then install dependencies:

```sh
pip install serles-acme
```

Create a config file from the example:

```sh
cp config.ini.example config.ini
# and then fill in values as needed.
```

Finally, tart the server with:

```sh
CONFIG=./config.ini python -m serles
```

Any client can connect to it now:

```sh
# either edit values in this script, or run certbot as usual
./examples-clients/certbot.sh
```

## Support

For any support/help, feel free to join Handshake's [Telegram](https://t.me/hns_tech) or [Discord](https://discord.gg/AtqtxGckqX) groups and we'll do our best to find out what's wrong.

If there's any problem with the code or have suggestions, [create a new issue](https://github.com/htools-org/htools-dane-ca/issues/new).

## License

[GPL-3.0 License](https://choosealicense.com/licenses/gpl-3.0/)

## Credit

Thanks to

- @dvtirol for [dvtirol/serles-acme](https://github.com/dvtirol/serles-acme) this project is forked from (backend modularity was very useful!)
- @brandondees for the idea of using CA this way
- @buffrr for advice on certificates
