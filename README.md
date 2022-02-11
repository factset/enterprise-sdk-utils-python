<img alt="FactSet" src="https://www.factset.com/hubfs/Assets/images/factset-logo.svg" height="56" width="290">

# FactSet SDK Utilities for Python

[![PyPi](https://img.shields.io/pypi/v/fds.sdk.utils)](https://pypi.org/project/fds.sdk.utils/)
[![Apache-2 license](https://img.shields.io/badge/license-Apache2-brightgreen.svg)](https://www.apache.org/licenses/LICENSE-2.0)

This repository contains a collection of utilities that supports FactSet's SDK in Python and facilitate usage of FactSet APIs.

## Installation

### Poetry

```python
poetry add fds.sdk.utils
```

### pip

```python
pip install fds.sdk.utils
```

## Usage

This library contains multiple modules, sample usage of each module is below.

### Authentication

First, you need to create the OAuth 2.0 client configuration that will be used to authenticate against FactSet's APIs:

1. Create a [new application](https://developer.factset.com/applications) on FactSet's Developer Portal.
2. When prompted, download the configuration file and move it to your development environment.

```python
from fds.sdk.utils.authentication import ConfidentialClient
import requests

client = ConfidentialClient('/path/to/config.json')
res = requests.get(
  'https://api.factset.com/analytics/lookups/v3/currencies',
  headers={
    'Authorization': 'Bearer ' + client.get_access_token()
  })

print(res.text)
```

## Modules

Information about the various utility modules contained in this library can be found below.

### Authentication

The [authentication module](src/fds/sdk/utils/authentication) provides helper classes that facilitate [OAuth 2.0](https://github.com/factset/oauth2-guidelines) authentication and authorization with FactSet's APIs. Currently the module has support for the [client credentials flow](https://github.com/factset/oauth2-guidelines#client-credentials-flow-1).

Each helper class in the module has the following features:

* Accepts a configuration file or `dict` that contains information about the OAuth 2.0 client, including the client ID and private key.
* Performs authentication with FactSet's OAuth 2.0 authorization server and retrieves an access token.
* Caches the access token for reuse and requests a new access token as needed when one expires.

#### Configuration

Classes in the authentication module require OAuth 2.0 client configuration information to be passed to constructors through a JSON-formatted file or a `dict`. In either case the format is the same:

```json
{
    "name": "Application name registered with FactSet's Developer Portal",
    "clientId": "OAuth 2.0 Client ID registered with FactSet's Developer Portal",
    "clientAuthType": "Confidential",
    "owners": ["USERNAME-SERIAL"],
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
        "qi": "First CRT Coefficient",
    }
}
```

If you're just starting out, you can visit FactSet's Developer Portal to [create a new application](https://developer.factset.com/applications) and download a configuration file in this format.

If you're creating and managing your signing key pair yourself, see the required [JWK parameters](https://github.com/factset/oauth2-guidelines#jwk-parameters) for public-private key pairs.

## Debugging

This library uses the [logging module](https://docs.python.org/3/howto/logging.html) to log various messages that will help you understand what it's doing. You can increase the log level to see additional debug information using standard conventions. For example:

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

Copyright 2021 FactSet Research Systems Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
