from flask import Flask, jsonify, request
import sqlite3
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from calendar import timegm
import jwt
import base64

app = Flask(__name__)
DATABASE = 'totally_not_my_privateKeys.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    return conn

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    db = get_db_connection()
    cursor = db.cursor()

    select = "SELECT * FROM keys WHERE exp > ?;"
    cursor.execute(select, (timegm(datetime.now(tz=timezone.utc).timetuple()),))
    rows = cursor.fetchall()
    db.close()

    jwks = {"keys": []}
    for row in rows:
        kid, priv_key_bytes, expiry = row
        priv_key = serialization.load_pem_private_key(priv_key_bytes, None)
        pub_key = priv_key.public_key()

        jwk = {
            "kid": str(kid),
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": base64.urlsafe_b64encode(pub_key.public_numbers().n.to_bytes((pub_key.public_numbers().n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(pub_key.public_numbers().e.to_bytes((pub_key.public_numbers().e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("="),
        }
        jwks["keys"].append(jwk)

    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def auth():
    expired = 'expired' in request.args and request.args['expired'] == 'true'
    db = get_db_connection()
    cursor = db.cursor()

    if expired:
        select = "SELECT kid, key, exp FROM keys WHERE exp <= ?;"
    else:
        select = "SELECT * FROM keys WHERE exp > ?;"
    cursor.execute(select, (timegm(datetime.now(tz=timezone.utc).timetuple()),))
    key_row = cursor.fetchone()
    db.close()

    if key_row:
        kid, priv_key_bytes, expiry = key_row
        jwt_token = jwt.encode(
            {"exp": expiry},
            priv_key_bytes,
            algorithm="RS256",
            headers={"kid": str(kid)},
        )
        return jsonify({"jwt": jwt_token})
    else:
        return jsonify({"error": "No valid key found"}), 404

def init_db():
    db = get_db_connection()
    db.execute(
        "CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);"
    )
    db.commit()
    db.close()

def generate_keys():
    db = get_db_connection()
    for i in range(5):
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_key_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        expiry = datetime.now(tz=timezone.utc) + timedelta(hours=(-1 if i % 2 == 0 else 1))
        db.execute("INSERT INTO keys (key, exp) VALUES(?, ?);", (priv_key_bytes, timegm(expiry.timetuple())))
    db.commit()
    db.close()

if __name__ == '__main__':
    init_db()
    generate_keys()
    print("Flask server running...")
    app.run(debug=True, port=8080)
