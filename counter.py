from flask import Flask, request, jsonify, make_response
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import base64

options = [
(1, "Yakuhito"),
(2, "Also Yakuhito"),
(3, "Definetly Yakuhito"),
(4, "Yakuhito, of course!")
]

pubkey_pem = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1dYYw3e/nRRmomgTaeF\n1+ocseg2RMlhDGP16daOmcd//oBudGWqphDs+0a1d75I1wmj/YlviiRhiwRgPo4j\nmXXb4akPyxnO44plK0IpO761gyod2WrxQXnCNmUYMVOSiZdE168WinrKcIijc8XY\nbWLexx4RwKS0j+cinSTbJiIVvhefSWYXxOpz18gEIu3xgkOx9aD853n8BXA4Bv5t\ncuwxZdF+ibIrE5TmNJe8kxJbfxsucDkamGvIWsummEMpuH4jGWEuTantYnNKG615\nWhsA7eI/9xCR036O7nNTIjk5KRR/rZ1ytgBMceerK5g/bk8hYII/surpqxjZ+N/0\nkwIDAQAB\n-----END PUBLIC KEY-----'
pubkey = RSA.importKey(pubkey_pem)

votes = []

app = Flask("Counter Server")

@app.route('/')
def index():
	return 'The counter zerver is working!'


@app.route('/submit', methods=['POST'])
def submit():
	global votes
	global pubkey_pem
	global options

	# Parse request
	data = request.get_json(force=True)
	if data.get('signed_vote', -1) == -1 or data.get('r', -1) == -1:
		return make_response(jsonify(error='bad request'), 200)
	signed_vote = str(data["signed_vote"])
	r = str(data["r"])

	try:
		signed_vote = bytes_to_long(base64.b64decode(signed_vote.encode()))
	except:
		return make_response(jsonify(error='bad b64 encoding!'), 200)

	# Decode vote
	decoded_vote = pow(signed_vote, pubkey.e, pubkey.n)
	decoded_vote = long_to_bytes(decoded_vote)

	# Search for correct vote and record it
	for option, strg in options:
		s = str(option).encode() + b'-' + r.encode()
		if s == decoded_vote:
			votes.append((str(option), signed_vote, r))
			return make_response(jsonify(message="Your vote has been recorded."), 200)

	# If no mach is found, the string that was sent wasn't formatted correctly
	return make_response(jsonify(error="Bad vote."), 200)


@app.route('/stats', methods=['GET'])
def stats():
	global votes
	global options

	# Set all vote counts to 0
	counter = {}
	for option, strg in options:
		counter[str(option)] = 0

	# Count the votes
	for vote in votes:
		counter[vote[0]] += 1

	# Return the answer as json
	return make_response(jsonify(counter))


if __name__=="__main__":
	app.run(host='127.0.0.1', port='2222')
