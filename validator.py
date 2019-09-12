from flask import Flask, request, jsonify, make_response
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import base64

privkey_pem = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAv1dYYw3e/nRRmomgTaeF1+ocseg2RMlhDGP16daOmcd//oBu\ndGWqphDs+0a1d75I1wmj/YlviiRhiwRgPo4jmXXb4akPyxnO44plK0IpO761gyod\n2WrxQXnCNmUYMVOSiZdE168WinrKcIijc8XYbWLexx4RwKS0j+cinSTbJiIVvhef\nSWYXxOpz18gEIu3xgkOx9aD853n8BXA4Bv5tcuwxZdF+ibIrE5TmNJe8kxJbfxsu\ncDkamGvIWsummEMpuH4jGWEuTantYnNKG615WhsA7eI/9xCR036O7nNTIjk5KRR/\nrZ1ytgBMceerK5g/bk8hYII/surpqxjZ+N/0kwIDAQABAoIBAA03TJTq7FrJpf6f\n6uvyL5Mjnypv+O+fXo4AiYfGmMA+a196Iib1WWgcWyyv9vDND92VKOKQ5PIMY+sP\njlDueGmtHlbj2oITckV9Kv0QliXY8lNGTBwsVXr0R1nXzxKjzHH8eiDQ/c7q1E4Z\njKX+ewhzKngOYk4wEi4Dr6cIWKq1fqaNfjMMJ6MlZJ6Ilc0RcOlK/VyEH18St0gT\nkEJs/Gn2B6Q4sVuFfjDAEOACHJfvQFNvI1qNhisvx6ZwgIyN8Z2yeNfE4xx5VZJR\nT3X52OYeEe3QJL7IaHl8qF3pL/wPh/ILIlq8xYReSQd8FxMkrXLWrBSC3AQ6A9eL\nxCaaDSECgYEAzC1FaCW5p/g1cvGl59V4ZSZ1AB8sCzGlnzxe0JAQa0/EeUOwOOJL\nlVncSbjEYCuYCuUw9HJBk5v8jb7hTIoSHVuHaUhBAuyenfEjlUaXgJ6gukp3lJCJ\nqLgsaaK23N7m7ZLkf0hAwOqTrIkLeEDuhmmTvRGMaWJugjRQoU4LqA8CgYEA7+gO\nfzIrRFSaoAH3CQ5jVtE39fTWJckD4p9IlOWNyCKQhFqDlhlTyaDJCHWf00cP+qNy\nQBRjUM4Z3GDKD2uNhdxkrGs7JwEHRglkHa+JGnC783kl6ALtWkID2IoCGrnisgxm\nMftkXxYWIagsvMzkWrbU8JuhuxHI77U9V6z3hz0CgYEAvhUjebstZaAhenpX/0Zw\niJLN+CgNI/q7e0yD5N1KO+2ON2r542th/JAlEokuYW4UZYhMFDdOr7JX5Eqhi1U7\nWhN9NFntFGDfpqD5hJ6sqzSC5Awx2aDaV7Xmuw2d+nCWQvUvPwQwLKn2g3kusWyZ\n447k2O8+bloSEavMqO900KcCgYEA3t6y0QF3ZnQ+bVVF/LjMGnQky66XXuTeYiLd\nV83lqD5MCVjZE5EV4KMo/13ei3Vh59L9qYAHP6MoLS4RqL+e6vNy5yZ6/mIbMro4\nssdG1DRUtvwd9er6OzZGwlx7Vf7IFeYk7lv/w8IN71h/rymdHpTpP1klp1b/V4kE\norXCAnUCgYBQ9VmKeMp+JkD9lUT1r8F10cGMB0EwETRGCV+MYdFwC8B81txb8ww3\neRbHvdClkS3nFxR3H7WZkUG7Zrw2zU8ldHphCcHBM8N8xsh5DH8D0I8XTQBUcbPe\nWOf6ut2+h7M9yyz10mfAyqtFyIBcH/JGp/B0Rxm1GXDh/2JI63BspA==\n-----END RSA PRIVATE KEY-----'
privkey = RSA.importKey(privkey_pem)

app = Flask("Validator Server")

allowed_voters = ["yakuhito{}".format(i) for i in range(100)]
voters = []

@app.route('/')
def index():
	return 'The validator server is working!'


@app.route('/validate', methods=['POST'])
def validate():
	global voters
	global allowed_voters
	global privkey

	# Parse request
	data = request.get_json(force=True)
	if data.get('username', -1) == -1 or data.get('vote',  -1) == -1:
		return make_response(jsonify(error='username and vote are required!'), 200)
	username = str(data['username'])
	vote = str(data['vote'])
	try:
		vote = bytes_to_long(base64.b64decode(vote.encode()))
	except:
		return make_respone(jsonify(error="can't decode vote!"), 200)

	# Check if user is allowed to vote
	if username not in allowed_voters:
		return make_response(jsonify(error="user isn't allowed to vote"), 200)

	# Check if user already voted
	if username in voters:
		return make_response(jsonify(error='you already voted!'), 200)

	# Sign vote
	signature = pow(vote, privkey.d, privkey.n)

	# Add voter to voters
	voters.append(username)

	# Return signed vote
	return make_response(jsonify(signature=base64.b64encode(long_to_bytes(signature)).decode()), 200)


if __name__ == "__main__":
	app.run(host='127.0.0.1', port='1111')
