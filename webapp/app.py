import jwt as pyjwt
import hmac
import hashlib
import time
import json
import base64
from flask import Flask, request, render_template, make_response, jsonify, redirect
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os

app = Flask(__name__)

with open("private.pem", "rb") as f:
    PRIVATE_KEY = f.read()
with open("public.pem", "rb") as f:
    PUBLIC_KEY = f.read()


def b64decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def make_jwks():
    pub = load_pem_public_key(PUBLIC_KEY)
    nums = pub.public_numbers()
    def _b64uint(n, length):
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()
    return {
        "keys": [{
            "kty": "RSA",
            "kid": "webapp-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": _b64uint(nums.n, 256),
            "e": _b64uint(nums.e, 3),
        }]
    }


def verify_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    try:
        header = json.loads(b64decode(parts[0]))
    except Exception:
        raise ValueError("Invalid header")

    alg = header.get("alg", "")

    if alg == "RS256":
        # Normal RSA verification via PyJWT
        return pyjwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

    elif alg == "HS256":
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        expected = hmac.new(PUBLIC_KEY, sig_input, hashlib.sha256).digest()
        actual = b64decode(parts[2])
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Invalid signature")
        try:
            return json.loads(b64decode(parts[1]))
        except Exception:
            raise ValueError("Invalid payload")

    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("token", "")
    return resp


@app.route("/login", methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    app_username = os.getenv('APP_USERNAME')
    app_password = os.getenv('APP_PASSWORD')

    if username == app_username and password == app_password:
        payload = {"sub": username, "role": "user", "iat": int(time.time())}
        token = pyjwt.encode(payload, PRIVATE_KEY, algorithm="RS256",
                         headers={"kid": "webapp-key-1"})
        resp = make_response(redirect("/"))
        resp.set_cookie("token", token)
    else:
        resp = make_response(render_template("login.html"))
    return resp
        


@app.route("/")
def index():
    token = request.cookies.get("token")
    if not token:
        resp = make_response(render_template("login.html"))
        return resp

    try:
        payload = verify_token(token)
    except Exception as e:
        return f"<h2>Ungueltiger Token: {e}</h2><p><a href='/'>Zurueck</a></p>", 401

    sub = payload.get('sub','unknown')
    role = payload.get('role','unknown')


    resp = make_response(render_template("index.html", username=sub, role=role))
    return resp

@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify(make_jwks())


@app.route("/public.pem")
def public_pem():
    return PUBLIC_KEY, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/vault")
def vault():

    FLAG = os.getenv('FLAG')
    token = request.cookies.get("token")
    if not token:
        return "<h2>Kein Token gefunden</h2><p><a href='/'>Zurueck</a></p>", 401

    try:
        payload = verify_token(token)
    except Exception as e:
        return f"<h2>Ungueltiger Token: {e}</h2><p><a href='/'>Zurueck</a></p>", 401

    resp = make_response()
    resp.headers["X-Supported-Algs"] = "RS256, HS256"

    if payload.get("role") == "admin":
        return f"<h1>Tresor geoeffnet!</h1><p>Flag: {FLAG}</p>"

    return (
        f"<h2>Zugang verweigert</h2>"
        f"<p>Deine Rolle: <b>{payload.get('role', 'unknown')}</b></p>"
        f"<p>Nur der <b>admin</b> hat Zugang zum Tresor.</p>"
        f"<p><a href='/'>Zurueck</a></p>"
    ), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
