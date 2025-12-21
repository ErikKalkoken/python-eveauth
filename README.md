# python-eveauth

An Python library for authorizing desktop apps with the EVE online SSO.

[![release](https://img.shields.io/pypi/v/python-eveauth?label=release)](https://pypi.org/project/python-eveauth/)
[![python](https://img.shields.io/pypi/pyversions/python-eveauth)](https://pypi.org/project/python-eveauth/)
[![license](https://img.shields.io/badge/license-MIT-green)](https://gitlab.com/ErikKalkoken/python-eveauth/-/blob/master/LICENSE)

## Description

python-eveauth is an library for authorizing Python scripts on desktops with the EVE online SSO. This allows obtaining SSO tokens with any Python script, e.g. CLI tools, GUI apps or jupiter notebooks.

> [!Note]
> This library requires a system with a local web browser and will therefore only work on desktop like machines.

## Installation

```sh
pip install python-eveauth
```

### Usage

First setup your EVE SSO app on developers.eveonline.com.
The callback should be: `http://127.0.0.1:8080/callback`

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
