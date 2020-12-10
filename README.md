
About
=====

POC of an offline server for IDA Lumina feature.

More details on https://www.synacktiv.com/publications/investigating-ida-lumina-feature.html

Instalation
===========

Python package installation
---------------------------

Download project and run `python lumina/setup.py` (or `pip install .`).

Server can also be used as a standalone script.  The command `lumina_server` won't be registered in the PATH though. You will have to run manually using `python3 lumina/lumina_server.py`.

Generate certificates
----------------------

This step is optionnal if you don't need using TLS. You will then have to modify the `LUMINA_TLS = NO` in `ida.cfg`.

Generate a new ROOT CA certificate and key using one of these lines
(you can remove the `-nodes` option to set a passphrase but keep in mind you will need to pass passphrase argument to server script):

```bash
# sha256WithRSAEncryption
openssl req -nodes -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -keyout luminaRootCAKey.pem -out luminaRootCAK.pem -days 365 -subj '/CN=www.fakerays.com/O=Fake Hexrays/C=XX'

# ecdsa-with-SHA256 (prime256v1)
openssl req -nodes -x509 -newkey rsa:4096 -sha512 -keyout luminaRootCAKey.pem -out luminaRootCA.pem -days 365 -subj '/CN=www.fakerays.com/O=Fake Hexrays/C=XX'
```

Client setup
------------

Copy the CA certificate (`luminaRootCA.pem`) to IDA config directory as `hexrays.crt`:
- Windows: ``%APPDATA%\Hex-Rays\IDA Pro\hexrays.crt``
- Linux/OSX: ``$HOME/.idapro/hexrays.crt``

e.g (linux): `cp luminaRootCA.pem $HOME/.idapro/hexrays.crt`

modify the IDA configuration file (``cfg/ida.cfg``), either in installation directory or (recommanded) user directory:
- Windows: ``%APPDATA%\Hex-Rays\IDA Pro\cfg\ida.cfg``
- Linux/OSX: ``$HOME/.idapro/hexrays.crt``

```c
// Lumina related parameters
LUMINA_HOST               = "localhost";  // Lumina server url (default : "lumina.hex-rays.com")
                                          // warning: keep the the semicolon
LUMINA_MIN_FUNC_SIZE      = 32            // default function size : 32
LUMINA_PORT               = 4443          // default port : 443
LUMINA_TLS                = YES           // enable TLS (default : YES)
```

First run
=========

Start the server
----------------

Usage:
```
usage: lumina_server [-h] [-i IP] [-p PORT] [-c CERT] [-k CERT_KEY]
                     [-l {NOTSET,DEBUG,INFO,WARNING}]
                     db

positional arguments:
  db                    database file

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        listening ip address (default: 127.0.0.1
  -p PORT, --port PORT  listening port (default: 4443
  -c CERT, --cert CERT  proxy certfile (no cert means TLS OFF).
  -k CERT_KEY, --key CERT_KEY
                        certificate private key
  -l {NOTSET,DEBUG,INFO,WARNING}, --log {NOTSET,DEBUG,INFO,WARNING}
                        log level bases on python logging value (default:info)

```

exemple:

```bash
lumina_server db.json --cert luminaRootCA.pem --key luminaRootCAKey.pem --ip 127.0.0.1 --port 4443 --log DEBUG
```

Start server, (re)start IDA with an idb database and push your first function using Lumina.
Hit `ctrl-c` to terminate server and save database.

**Important**: keep in mind that the database is only saved or updated on server exit (`ctrl-c`).
