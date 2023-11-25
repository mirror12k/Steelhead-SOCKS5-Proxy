#!/bin/bash
pip install -r test/requirements.txt
openssl genrsa -out key.pem 4096
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=OrganizationalUnit/CN=www.example.com"

./test/unit_test.py
