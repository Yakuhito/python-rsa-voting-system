#!/usr/bin/python3
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from Crypto.PublicKey import RSA

import string
import os
import requests
import random
import math
import base64
import json

vote_subj = "If you could vote the next president of your country, who would that be?"

options = [
(1, "Yakuhito"),
(2, "Also Yakuhito"),
(3, "Definetly Yakuhito"),
(4, "Yakuhito, of course!")
]

pubkey_pem = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1dYYw3e/nRRmomgTaeF\n1+ocseg2RMlhDGP16daOmcd//oBudGWqphDs+0a1d75I1wmj/YlviiRhiwRgPo4j\nmXXb4akPyxnO44plK0IpO761gyod2WrxQXnCNmUYMVOSiZdE168WinrKcIijc8XY\nbWLexx4RwKS0j+cinSTbJiIVvhefSWYXxOpz18gEIu3xgkOx9aD853n8BXA4Bv5t\ncuwxZdF+ibIrE5TmNJe8kxJbfxsucDkamGvIWsummEMpuH4jGWEuTantYnNKG615\nWhsA7eI/9xCR036O7nNTIjk5KRR/rZ1ytgBMceerK5g/bk8hYII/surpqxjZ+N/0\nkwIDAQAB\n-----END PUBLIC KEY-----'

VALIDATOR_ADDR = "http://127.0.0.1:1111/validate"
COUNTER_ADDR = "http://127.0.0.1:2222/submit"
STATS_ADDR = "http://127.0.0.1:2222/stats"

def getSignedVote(username, vote):
	global pubkey_pem
	global VALIDATOR_ADDR
	pubkey = RSA.importKey(pubkey_pem)

	# Choose r
	r = random.randint(2, pubkey.n)
	while math.gcd(r, pubkey.n) != 1:
		r += 1

	# Calculate blinding factor
	blinding_factor = pow(r, pubkey.e, pubkey.n)

	# Calculate blinding vote
	blinded_vote = (int(vote) * blinding_factor) % pubkey.n

	# Get blinded signature
	enc_vote = base64.b64encode(long_to_bytes(blinded_vote)).decode()
	req = requests.post(VALIDATOR_ADDR, json={'username': username, 'vote': enc_vote})
	resp = json.loads(req.text)
	blinded_signature = bytes_to_long(base64.b64decode(resp["signature"]))

	# Calculate signature
	r_inv = inverse(r, pubkey.n)
	signature = blinded_signature * r_inv % pubkey.n

	return signature


def submitSignedVote(vote, r):
	global COUNTER_ADDR

	vote = base64.b64encode(long_to_bytes(vote)).decode()
	req = requests.post(COUNTER_ADDR, json={"signed_vote": vote, "r": str(r)})

	print(req.text)


def printStats():
	global STATS_ADDR

	req = requests.get(STATS_ADDR)
	stats = json.loads(req.text)

	print()
	print("Thank you for taking the time to vote! Here are the vote stats:")
	for key, value in stats.items():
		print("Option {} has {} votes.".format(key, value))
	print()


def encodeVote(vote):
	alphabet = string.ascii_letters + "0123456789"
	r = ''.join([random.choice(alphabet) for i in range(64)])
	enc = "{}-{}".format(vote, r)
	return bytes_to_long(enc.encode()), r


def main():
	global vote_subj
	global options

	# Intro
	print("Welcome to y@kuhi.to's voting system demo!")
	print("PLEASE NOTE THAT YOUR VOTE IS FINAL")
	print("No pressure!")
	print()
	print("Today's voting topic:")
	print(vote_subj)
	print()
	print("Yout voting options:")
	for opt in options:
		print("OPTION {}: {}".format(opt[0], opt[1]))
	print()

	# Get user's username
	print("Username:", end=" ")
	username = input()

	# Get the user's vote
	print("Your vote:", end=" ")
	try:
		vote = int(input()) # This is python3, please note that running this line on python2 will result in a code execution vuln
	except:
		print("Nope.")
		return ""

	# See if the vote is valid
	valid = False
	for opt in options:
		if opt[0] == vote:
			valid = True
	if valid == False:
		print("You were the chosen one! I trusted you!")
		return ""

	# Encode Vote
	vote, r = encodeVote(vote)

	# Get signed vote
	try:
		signed_vote = getSignedVote(username, vote)
	except:
		print("Something went wrong with vote signing :(")
		return ""

	# Send vote to counter
	submitSignedVote(signed_vote, r)

	# After the vote has bin submitted, print the stats
	printStats()


if __name__ == "__main__":
	main()
