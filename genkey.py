#!/usr/bin/python3
from Crypto.PublicKey import RSA
from Crypto import Random
import os

if os.path.isfile('public.pem'):
	print("public.pem already exists! Exiting...")
	os.exit(1)

print("Generating new keypair, please wait...")

random_generator = Random.new().read
key = RSA.generate(2048, random_generator)

print("Key generated, saving to files...")

open('public.pem', 'wb').write(key.publickey().exportKey('PEM'))
open('private.pem', 'wb').write(key.exportKey('PEM'))

print("Done!")
