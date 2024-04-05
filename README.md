<img alt="FactSet" src="https://www.factset.com/hubfs/Assets/images/factset-logo.svg" height="56" width="290">

# FactSet SDK Utilities for Python

[![PyPi](https://img.shields.io/pypi/v/fds.sdk.utils)](https://pypi.org/project/fds.sdk.utils/)
[![Apache-2 license](https://img.shields.io/badge/license-Apache2-brightgreen.svg)](https://www.apache.org/licenses/LICENSE-2.0)

This repository contains a collection of utilities that supports FactSet's SDK in Python and facilitate usage of FactSet
APIs.

## Installation

### Poetry

```sh
poetry add fds.sdk.utils
```

### pip

```sh
pip install fds.sdk.utils
```

## Usage

This library contains multiple modules, sample usage of each module is below.

### Authentication

First, you need to create the OAuth 2.0 client configuration that will be used to authenticate against FactSet's APIs:

1. [Create a new application](https://developer.factset.com/learn/authentication-oauth2#creating-an-application) on
   FactSet's Developer Portal.
2. When prompted, download the configuration file and move it to your development environment.

```python
from fds.sdk.utils.authentication import ConfidentialClient
import requests

# The ConfidentialClient instance should be reused in production environments.
client = ConfidentialClient(
  config_path='/path/to/config.json'
)
res = requests.get(
  'https://api.factset.com/analytics/lookups/v3/currencies',
  headers={
    'Authorization': 'Bearer ' + client.get_access_token()
  })

print(res.text)
```

### Configure a Proxy

You can pass proxy settings to the ConfidentialClient if necessary.
The `proxy` parameter takes a URL to tell the request library which proxy should be used.

If necessary it is possible to set custom `proxy_headers` as dictionary.

```python
from fds.sdk.utils.authentication import ConfidentialClient

client = ConfidentialClient(
  config_path='/path/to/config.json',
  proxy="http://secret:password@localhost:5050",
  proxy_headers={
    "Custom-Proxy-Header": "Custom-Proxy-Header-Value"
  }
)
```

### Custom SSL Certificate

If you have proxies or firewalls which are using custom TLS certificates,
you are able to pass a custom pem file (`ssl_ca_cert` parameter) so that the
request library is able to verify the validity of that certificate. If a
ca cert is passed it is validated regardless if `verify_ssl` is set to false.

With `verify_ssl` it is possible to disable the verifications of certificates.
Disabling the verification is not recommended, but it might be useful during
local development or testing

```python
from fds.sdk.utils.authentication import ConfidentialClient

client = ConfidentialClient(
  config_path='/path/to/config.json',
  verify_ssl=True,
  ssl_ca_cert='/path/to/ca.pem'
)
```

### Request Retries

In case the request retry behaviour should be customized, it is possible to pass a `urllib3.Retry` object to
the `ConfidentialClient`.

```python
from urllib3 import Retry
from fds.sdk.utils.authentication import ConfidentialClient

client = ConfidentialClient(
  config_path='/path/to/config.json',
  retry=Retry(
    total=5,
    backoff_factor=0.1,
    status_forcelist=[500, 502, 503, 504]
  )
)
```

## Modules

Information about the various utility modules contained in this library can be found below.

### Authentication

The [authentication module](src/fds/sdk/utils/authentication) provides helper classes that
facilitate [OAuth 2.0](https://developer.factset.com/learn/authentication-oauth2) authentication and authorization with
FactSet's APIs. Currently the module has support for
the [client credentials flow](https://github.com/factset/oauth2-guidelines#client-credentials-flow-1).

Each helper class in the module has the following features:

* Accepts a configuration file or `dict` that contains information about the OAuth 2.0 client, including the client ID
  and private key.
* Performs authentication with FactSet's OAuth 2.0 authorization server and retrieves an access token.
* Caches the access token for reuse and requests a new access token as needed when one expires.
  * In order for this to work correctly, the helper class instance should be reused in production environments.

#### Configuration

Classes in the authentication module require OAuth 2.0 client configuration information to be passed to constructors
through a JSON-formatted file or a `dict`. In either case the format is the same:

```json
{
  "name": "Application name registered with FactSet's Developer Portal",
  "clientId": "OAuth 2.0 Client ID registered with FactSet's Developer Portal",
  "clientAuthType": "Confidential",
  "owners": [
    "USERNAME-SERIAL"
  ],
  "jwk": {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "Key ID",
    "d": "ECC Private Key",
    "n": "Modulus",
    "e": "Exponent",
    "p": "First Prime Factor",
    "q": "Second Prime Factor",
    "dp": "First Factor CRT Exponent",
    "dq": "Second Factor CRT Exponent",
    "qi": "First CRT Coefficient"
  }
}
```

If you're just starting out, you can visit FactSet's Developer Portal
to [create a new application](https://developer.factset.com/applications) and download a configuration file in this
format.

If you're creating and managing your signing key pair yourself, see the
required [JWK parameters](https://github.com/factset/oauth2-guidelines#jwk-parameters) for public-private key pairs.

## Debugging

This library uses the [logging module](https://docs.python.org/3/howto/logging.html) to log various messages that will
help you understand what it's doing. You can increase the log level to see additional debug information using standard
conventions. For example:

```python
logging.getLogger('fds.sdk.utils').setLevel(logging.DEBUG)
```

or

```python
logging.getLogger('fds.sdk.utils.authentication').setLevel(logging.DEBUG)
```

# Contributing

Please refer to the [contributing guide](CONTRIBUTING.md).

# Copyright

Copyright 2022 FactSet Research Systems Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
