#!/bin/bash

cp docker-compose.yml ../../rekor/
cd ../../rekor
docker compose up -d --wait
