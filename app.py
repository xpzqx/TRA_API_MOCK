
import flask
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import random
import time
import re
import hmac
import hashlib
import base64
import secrets

app = Flask(__name__)
CORS(app)

# Secret key for HMAC generation (should be securely stored)
HMAC_SECRET_KEY = secrets.token_hex(32)

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_jwt_token(phone):
    payload = {
        'phone': phone,
        'exp': int(time.time()) + 3600,
        'iat': int(time.time())
    }
    return jwt.encode(payload, 'your_secret_key', algorithm='HS256')

def generate_hmac_key(phone):
    """
    Generate a secure HMAC key based on phone number and a secret
    """
    # Combine phone with a secret key
    message = f"{phone}:{int(time.time())}"
    
    # Create HMAC
    hmac_digest = hmac.new(
        HMAC_SECRET_KEY.encode(), 
        message.encode(), 
        hashlib.sha256
    ).digest()
    
    # Base64 encode the HMAC
    return base64.b64encode(hmac_digest).decode()

def verify_hmac(hmac_key, payload, received_hmac):
    """
    Verify the HMAC for a given payload
    """
    try:
        # Recreate HMAC
        calculated_hmac = hmac.new(
            hmac_key.encode(), 
            payload.encode(), 
            hashlib.sha256
        )
        
        # Compare with received HMAC
        return hmac.compare_digest(
            base64.b64encode(calculated_hmac.digest()).decode(), 
            received_hmac
        )
    except Exception:
        return False

@app.route('/cmt/auth/loginWithOTP', methods=['POST'])
def login_with_otp():
    data = request.json
    phone = data.get('phone')
    otp = data.get('otp')
    language = request.headers.get('Accept-Language', 'en')
    
    try:
        # Generate JWT token
        token = generate_jwt_token(phone)
        
        # Generate HMAC key
        hmac_key = generate_hmac_key(phone)
        
        return jsonify({
            "data": {
                "token": token,
                "key": hmac_key  # Generated HMAC key
            },
            "status": 200,
            "message": "تم التحقق من المستخدم." if language == 'ar' else "User verified."
        }), 200
    except Exception as e:
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

@app.route('/cmt/chatbot/raiseNewComplain', methods=['POST'])
def raise_new_complaint():
    # Get HMAC details from headers
    hmac_key = request.headers.get('Hmac-Key')
    received_hmac = request.headers.get('Hmac')
    
    # Convert request data to string for HMAC verification
    payload = str(request.json)
    
    # Verify HMAC before processing
    if not hmac_key or not received_hmac or not verify_hmac(hmac_key, payload, received_hmac):
        return jsonify({
            "data": None,
            "status": 401,
            "message": "غير مصرح به" if request.headers.get('Accept-Language', 'en') == 'ar' else "Unauthorized"
        }), 401
    
    try:
        # Process complaint if HMAC is valid
        return jsonify({
            "data": None,
            "status": 200,
            "message": "شكرا ، سيتم النظر في الطلب المقدم ، وسيتم التواصل معك" if request.headers.get('Accept-Language', 'en') == 'ar' else "Thank you, the introduction will be considered, and you will be contacted."
        }), 200
    
    except Exception as e:
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

# Similar HMAC verification can be added to other endpoints that require authentication
@app.route('/cmt/chatbot/getComplaintFields', methods=['POST'])
def get_complaint_fields():
    # HMAC verification similar to raiseNewComplain
    hmac_key = request.headers.get('Hmac-Key')
    received_hmac = request.headers.get('Hmac')
    
    payload = str(request.json)
    
    if not hmac_key or not received_hmac or not verify_hmac(hmac_key, payload, received_hmac):
        return jsonify({
            "data": None,
            "status": 401,
            "message": "غير مصرح به" if request.headers.get('Accept-Language', 'en') == 'ar' else "Unauthorized"
        }), 401
    
    telecom_data = {
        "complainProviders": [
            {"code": "20", "value": "Oman Telecommunications Company (Omantel)"},
            {"code": "21", "value": "Omani Qatari Telecommunications Company (Ooredoo)"}
        ],
        "serviceTypes": [
            {
                "code": "TF", 
                "value": "Telecom Fixed",
                "subType": [
                    {"code": "1", "value": "ADSL"},
                    {"code": "2", "value": "5G"}
                ]
            }
        ],
        "customerTypes": [
            {"code": "C", "value": "Corporate"},
            {"code": "I", "value": "Individual"}
        ],
        "complainTypes": [
            {"code": "1", "value": "Billing & payment", "locationRequired": False},
            {"code": "2", "value": "Quality of service", "locationRequired": True}
        ]
    }
    
    return jsonify({
        "data": telecom_data,
        "status": 200,
        "message": ""
    }), 200

# Other existing routes remain the same...

if __name__ == '__main__':
    app.run(debug=True)
