#!/bin/bash

#NOTE: This assumes the docker run as found in the README, exposing on port 9090.
# Any client id works; with a clients file (CLIENTS) the entry's claims are added
# and its flows/allowed_resources are enforced.
curl -XPOST http://localhost:9090/token \
  -d grant_type=client_credentials \
  -d client_id=integration \
  -d client_secret=ignored \
  -d resource=http://localhost:8083 \
  -v
