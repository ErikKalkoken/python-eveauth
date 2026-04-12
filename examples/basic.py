import os

import requests

from eveauth import Client

# Create an auth client
c = Client(client_id=os.getenv("SSO_CLIENT_ID"))

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
# Refresh the token
# c.refresh_token(token)
