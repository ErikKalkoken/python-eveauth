# python-eveauth

An Python library for authorizing desktop apps with the EVE online SSO.

[![release](https://img.shields.io/pypi/v/python-eveauth?label=release)](https://pypi.org/project/python-eveauth/)
[![python](https://img.shields.io/pypi/pyversions/python-eveauth)](https://pypi.org/project/python-eveauth/)
[![CI/CD](https://github.com/ErikKalkoken/python-eveauth/actions/workflows/cicd.yaml/badge.svg)](https://github.com/ErikKalkoken/python-eveauth/actions/workflows/cicd.yaml)
[![codecov](https://codecov.io/gh/ErikKalkoken/python-eveauth/graph/badge.svg?token=NBGLASsNXq)](https://codecov.io/gh/ErikKalkoken/python-eveauth)
[![license](https://img.shields.io/badge/license-MIT-green)](https://gitlab.com/ErikKalkoken/python-eveauth/-/blob/master/LICENSE)

## Description

python-eveauth is a library for authorizing Python scripts on desktops with the EVE online SSO. This allows obtaining SSO tokens with any Python script, e.g. CLI tools, GUI apps or Jupiter notebooks.

## Installation

```sh
pip install python-eveauth
```

### Usage

First you need to create an EVE SSO app for your script on [Eve Online's developers site](https://developers.eveonline.com/). The default callback for your SSO app is: `http://127.0.0.1:8080/callback`

Then you can start authorizing your script with **eveauth**.

Below is an basic example that show how you can use **eveauth**. It first authorizes the script and obtains a token. Then fetches the wallet balance for the authorized character with the token. The token can later be refreshed as needed.

```py
import requests
from eveauth import Client

# Create an auth client
c = Client(client_id="YOUR-SSO-CLIENT-ID")

# Authorize the current script with the character wallet scope
token = c.authorize("esi-wallet.read_character_wallet.v1")

# Request the wallet balance for the authorized character
r = requests.get(
    url=f"https://esi.evetech.net/characters/{token.character_id}/wallet",
    headers={"Authorization": f"Bearer {token.access_token}"},
)
r.raise_for_status()

# Print the balance
print(r.text)


# Refresh the token
# c.refresh_token(token)
```
