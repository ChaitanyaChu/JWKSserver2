from flask import Flask, jsonify, request
import jwt
import datetime

# Configuration
SECRET_KEY = 'your_secret_key_here'  # Ensure this key is consistently used for signing and verification
ALGORITHM = 'HS256'
KID = 'mykeyid'

app = Flask(__name__)

def get_jwt_payload(username):
    return {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }

def get_jwt_headers():
    return {"kid": KID}

@app.route('/auth', methods=['POST'])
def auth():
    auth_data = request.json
    username = auth_data.get('username')
    password = auth_data.get('password')

    # Placeholder authentication check
    if username == "userABC" and password == "password123":
        payload = get_jwt_payload(username)
        headers = get_jwt_headers()
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM, headers=headers)
        # Return JWT in a standard JSON structure
        return jsonify({'jwt': token})
    else:
        return jsonify({'error': "Invalid credentials"}), 401

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # Simplified JWKS endpoint for demonstration with HS256
    # Note: In practice, HS256 does not use JWKS for public key sharing
    return jsonify({
        "keys": [
            {
                "kty": "oct",
                "k": SECRET_KEY,  # Not suitable for public exposure in real-world applications
                "kid": KID,
                "alg": ALGORITHM
            }
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

