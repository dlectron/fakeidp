#!/bin/bash

#NOTE: This assumes the docker run as found in the README, exposing on port 9090.
# Mints a user's access token on the legacy path, then exchanges it for one
# targeted at a service, naming the integration client as the acting party.
# Not claim.json: its exp is in 2019, and an expired subject token is refused.

SUBJECT=$(curl -s -d '{"sub": "F82E617D", "name": "Arie Ministrone", "scope": "openid profile"}' -H "Content-Type: application/json" -XPOST http://localhost:9090/token)
ACTOR=$(curl -s -d '{"sub": "integration", "scope": "openid"}' -H "Content-Type: application/json" -XPOST http://localhost:9090/token)

curl -XPOST http://localhost:9090/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=integration \
  -d client_secret=ignored \
  -d subject_token="$SUBJECT" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token="$ACTOR" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d resource=http://localhost:8083 \
  -v
