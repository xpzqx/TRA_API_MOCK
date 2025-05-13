import flask
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import time
import hmac
import hashlib
import base64
import secrets
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Secret keys (in production, use environment variables)
JWT_SECRET_KEY = secrets.token_hex(32)
HMAC_SECRET_KEY = secrets.token_hex(32)



@app.route('/')
def home():
    return jsonify({
        "message": "TRA API Mock Service is running",
        "status": 200
    }), 200
def generate_jwt_token(phone):
    """Generate a JWT token for the user"""
    payload = {
        'phone': phone,
        'exp': int(time.time()) + 3600,  # Token expires in 1 hour
        'iat': int(time.time())
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def generate_hmac_key(phone):
    """Generate a secure HMAC key"""
    message = f"{phone}:{int(time.time())}"
    hmac_digest = hmac.new(
        HMAC_SECRET_KEY.encode(), 
        message.encode(), 
        hashlib.sha256
    ).digest()
    return base64.b64encode(hmac_digest).decode()

def verify_hmac(hmac_key, payload, received_hmac):
    """Verify the HMAC for a given payload"""
    try:
        calculated_hmac = hmac.new(
            hmac_key.encode(), 
            payload.encode(), 
            hashlib.sha256
        )
        return hmac.compare_digest(
            base64.b64encode(calculated_hmac.digest()).decode(), 
            received_hmac
        )
    except Exception as e:
        logger.error(f"HMAC verification error: {e}")
        return False

@app.route('/cmt/auth/sendLoginOTP', methods=['POST'])
def send_login_otp():
    """Send login OTP"""
    try:
        data = request.get_json()
        phone = data.get('phone')
        language = request.headers.get('Accept-Language', 'en')

        # Validate phone number
        if not phone or len(phone) < 8 or len(phone) > 13:
            return jsonify({
                "data": None,
                "status": 400,
                "message": "رقم الهاتف غير صالح" if language == 'ar' else "Invalid phone number"
            }), 400

        # Static OTP for testing
        otp = "123456"
        
        logger.info(f"OTP sent to phone: {phone}")
        
        return jsonify({
            "data": None,
            "status": 200,
            "message": "تم إرسال رمز التحقق" if language == 'ar' else "OTP sent successfully"
        }), 200
    
    except Exception as e:
        logger.error(f"Error in send_login_otp: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

@app.route('/cmt/auth/loginWithOTP', methods=['POST'])
def login_with_otp():
    """Login with OTP"""
    try:
        data = request.get_json()
        phone = data.get('phone')
        otp = data.get('otp')
        language = request.headers.get('Accept-Language', 'en')

        # Validate inputs
        if not phone or not otp:
            return jsonify({
                "data": None,
                "status": 400,
                "message": "معلومات غير كاملة" if language == 'ar' else "Incomplete information"
            }), 400

        # Static OTP validation for testing
        if otp != "123456":
            return jsonify({
                "data": None,
                "status": 401,
                "message": "رمز التحقق غير صحيح" if language == 'ar' else "Invalid OTP"
            }), 401

        # Generate tokens
        jwt_token = generate_jwt_token(phone)
        hmac_key = generate_hmac_key(phone)
        
        logger.info(f"User logged in: {phone}")
        
        return jsonify({
            "data": {
                "token": jwt_token,
                "key": hmac_key
            },
            "status": 200,
            "message": "تم التحقق من المستخدم" if language == 'ar' else "User verified"
        }), 200
    
    except Exception as e:
        logger.error(f"Error in login_with_otp: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

@app.route('/cmt/chatbot/sendLoginOTP', methods=['POST'])
def chatbot_send_login_otp():
    """Chatbot send login OTP (duplicate of send_login_otp for compatibility)"""
    return send_login_otp()

@app.route('/cmt/chatbot/raiseNewComplain', methods=['POST'])
def raise_new_complaint():
    """Raise a new complaint with HMAC verification"""
    try:
        # Get HMAC details from headers
        hmac_key = request.headers.get('Hmac-Key')
        received_hmac = request.headers.get('Hmac')
        
        # Get request data
        data = request.get_json()
        payload = str(data)
        language = request.headers.get('Accept-Language', 'en')

        # Verify HMAC
        if not hmac_key or not received_hmac or not verify_hmac(hmac_key, payload, received_hmac):
            return jsonify({
                "data": None,
                "status": 401,
                "message": "غير مصرح به" if language == 'ar' else "Unauthorized"
            }), 401

        # Validate complaint data
        required_fields = ['complainProvider', 'serviceType', 'customerType', 'complainType']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "data": None,
                    "status": 400,
                    "message": f"Missing {field}"
                }), 400

        logger.info(f"New complaint raised: {data}")
        
        return jsonify({
            "data": None,
            "status": 200,
            "message": "شكرا ، سيتم النظر في الطلب المقدم" if language == 'ar' else "Thank you, your complaint will be processed"
        }), 200
    
    except Exception as e:
        logger.error(f"Error in raise_new_complaint: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

@app.route('/cmt/chatbot/getComplaintFields', methods=['POST'])
def get_complaint_fields():
    """Get complaint-related fields"""
    try:
        # Get HMAC details from headers
        hmac_key = request.headers.get('Hmac-Key')
        received_hmac = request.headers.get('Hmac')
        
        # Get request data
        data = request.get_json()
        payload = str(data)
        language = request.headers.get('Accept-Language', 'en')

        # Verify HMAC
        if not hmac_key or not received_hmac or not verify_hmac(hmac_key, payload, received_hmac):
            return jsonify({
                "data": None,
                "status": 401,
                "message": "غير مصرح به" if language == 'ar' else "Unauthorized"
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
    
    except Exception as e:
        logger.error(f"Error in get_complaint_fields: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

@app.route('/cmt/chatbot/getLocationDetails', methods=['GET'])
def get_location_details():
    """Get location details"""
    try:
        location_data = {
            "governorates": ["Muscat", "Dhofar"],
            "wilayas": [
                {"code": "30", "desc": "Muscat", "villages": ["Seeb", "Bawshar"]},
                {"code": "31", "desc": "Al Batinah", "villages": ["Sohar", "Rustaq"]}
            ]
        }
        
        return jsonify({
            "data": location_data,
            "status": 200,
            "message": ""
        }), 200
    
    except Exception as e:
        logger.error(f"Error in get_location_details: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
