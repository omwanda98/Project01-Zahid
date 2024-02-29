#ZAHID JAMAL
from flask import Flask, request, jsonify
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Create Flask app instance
app = Flask(__name__)
# Dictionary to store generated keys
keys = {}


# Function to generate a new RSA key pair and store it in the keys dictionary
def generate_key_pair():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Extract the corresponding public key
    public_key = private_key.public_key()
    # Generate a unique key ID
    kid = str(datetime.datetime.timestamp(datetime.datetime.now()))
    # Store the keys along with an expiration time
    keys[kid] = {
        "private_key": private_key,
        "public_key": public_key,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    return kid, private_key, public_key


# Define route for authentication to generate JWT
@app.route('/auth', methods=['POST'])
def authenticate():
    # Check if the 'expired' parameter is present in the request
    expired = request.args.get('expired')

    if expired:
        # Find an expired key or generate a new key pair if none is expired
        kid, private_key, _ = next(
            (
                (k, key['private_key'], key['public_key'])
                for k, key in keys.items()
                if key['exp'] < datetime.datetime.utcnow()
            ),
            generate_key_pair(),
        )
        # Set expiration time in the past for an expired token
        expiration = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    else:
        # Generate a new key pair for a valid token
        kid, private_key, _ = generate_key_pair()
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

    # Encode the JWT using the private key and return it in the response
    token = jwt.encode({"kid": kid, "exp": expiration}, private_key, algorithm='RS256')
    return jsonify({"token": token})


# Define route to return JSON Web Key Set (JWKS)
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # Prepare a list of valid public keys for the JSON Web Key Set (JWKS)
    valid_keys = []
    for kid, key_info in keys.items():
        # Check if the key is still valid
        if key_info['exp'] > datetime.datetime.utcnow():
            # Serialize the public key to PEM format
            public_key = key_info['public_key'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('utf-8')
            # Append the key details to the valid keys list
            valid_keys.append({
                "alg": "RS256",
                "e": "AQAB",
                "kid": kid,
                "kty": "RSA",
                "n": public_key.split('\n')[1],
                "use": "sig",
            })

    # Return the JSON Web Key Set (JWKS) containing the valid public keys
    return jsonify({"keys": valid_keys})


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True, port=8080)
