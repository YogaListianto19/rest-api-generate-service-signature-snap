from flask import Flask, request, session, url_for, redirect, jsonify
from flask_restful import Resource, Api
from flask_cors import CORS
from functools import wraps

import rsa, base64, hashlib, hmac, requests, json
import datetime, json, pytz
import logging

_logger = logging.getLogger(__name__)

app = Flask(__name__)
app.jinja_env.filters["zip"] = zip
app.config["SECRET_KEY"] = "generateServiceSignatureSNAP"

# deklarasi api
api = Api(app)
CORS(app)

def validate_header_service(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        data = request.json
        client_secret = request.headers.get("client_secret")
        http_method = request.headers.get("http_method")
        relative_url = request.headers.get("relative_url")
        token = request.headers.get("token")
        iso_timestamp = request.headers.get("iso_timestamp")
        content_type = request.headers.get('Content-Type')
        
        # not data:
        # Mandatory Header
        if content_type != 'application/json' or not content_type:
            return jsonify({"responseCode":500, "responseMessage":"Content-Type not supported!"})
        if not client_secret:
            return jsonify({"responseCode":500, "responseMessage":"Invalid mandatory field [client_secret]"})
        if not http_method:
            return jsonify({"responseCode":500, "responseMessage":"Invalid mandatory field [http_method]"})
        if not relative_url:
            return jsonify({"responseCode":500, "responseMessage":"Invalid mandatory field [relative_url]"})
        if not token:
            return jsonify({"responseCode":500, "responseMessage":"Invalid mandatory field [token]"})
        if not iso_timestamp:
            return jsonify({"responseCode":500, "responseMessage":"Invalid mandatory field [iso_timestamp]"})
        
        return f(*args, **kwargs)
    return decorator

def _generateServiceSignature(client_secret, http_method, relative_url, token, iso_timestamp, request_body=b''):
    signature = hmac.new(client_secret.encode(), digestmod=hashlib.sha512)
    string_to_sign = http_method + ':' + relative_url + ':' + token + ':' + hashlib.sha256(request_body).hexdigest() + ':' + iso_timestamp
    signature.update(string_to_sign.encode())
    return base64.b64encode(signature.digest()).decode('UTF-8')


class GenerateServiceSignature(Resource):
    # Method get dan post
    @validate_header_service
    def post(self):
        data = request.json
        client_secret = request.headers.get("client_secret")
        http_method = request.headers.get("http_method")
        relative_url = request.headers.get("relative_url")
        token = request.headers.get("token")
        iso_timestamp = request.headers.get("iso_timestamp")
        content_type = request.headers.get('Content-Type')
        body = json.dumps(data, separators=(',',':')).encode()
        try:
            signature = _generateServiceSignature(client_secret, http_method, relative_url, token, iso_timestamp, body)
            return jsonify({"responseCode":200, "responseMessage":"{}".format(signature)})
        except err:
            print(err)
            return jsonify({"responseCode":500, "responseMessage":"{}".format(err)})
        
    def get(self):
        return jsonify({"Hello World!"})
        
        
api.add_resource(GenerateServiceSignature, '/v1.0/generateServiceSignature', methods=["GET","POST"])

if __name__ == "__main__":
    app.run(debug=True, port=6300)
