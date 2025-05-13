
from flask import Flask, request, jsonify
from flask_cors import CORS
from utils import validate_phone, generate_otp
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/cmt/auth/sendLoginOTP', methods=['POST'])
def send_login_otp():
    """
    Send login OTP endpoint
    
    Request Body:
    {
        "phone": "91119609",
        "loginChannel": "CHATBOT"
    }
    
    Responses:
    - Success: OTP sent (status 200)
    - Failure: Invalid phone number (status 500)
    """
    try:
        # Parse request data
        data = request.get_json()
        phone = data.get('phone')
        login_channel = data.get('loginChannel', 'CHATBOT')

        # Validate phone number
        if not validate_phone(phone):
            return jsonify({
                "data": None,
                "status": 500,
                "message": "الحد الأقصى لطول رقم الهاتف هو 8 / 13."
            }), 500

        # Generate OTP
        otp = generate_otp()
        
        # In a real scenario, you would:
        # 1. Store OTP in a database with expiration
        # 2. Send OTP via SMS or another communication channel
        logger.info(f"OTP {otp} sent to phone: {phone}")
        
        return jsonify({
            "data": None,
            "status": 200,
            "message": "لقد تم إرسال كلمة السر لمرة واحدة بنجاح."
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
    """
    Login with OTP endpoint
    
    Request Body:
    {
        "phone": "91119609",
        "otp": "203294"
    }
    
    Responses:
    - Success: Token and HMAC key (status 200)
    - Failure: Invalid OTP or phone (status 500)
    """
    try:
        # Parse request data
        data = request.get_json()
        phone = data.get('phone')
        otp = data.get('otp')

        # Validate inputs
        if not phone or not otp:
            return jsonify({
                "data": None,
                "status": 500,
                "message": "معلومات غير كاملة"
            }), 500

        # Validate phone number format
        if not validate_phone(phone):
            return jsonify({
                "data": None,
                "status": 500,
                "message": "رقم الهاتف غير صالح"
            }), 500

        # Check if phone exists in OTP storage
        if phone not in OTP_STORAGE:
            return jsonify({
                "data": None,
                "status": 500,
                "message": "لم يتم إرسال OTP لهذا الرقم"
            }), 500

        # Retrieve stored OTP information
        otp_info = OTP_STORAGE[phone]

        # Check OTP validity
        if otp != otp_info['otp']:
            # Increment attempts
            otp_info['attempts'] += 1

            # Block after max attempts
            if otp_info['attempts'] >= otp_info['max_attempts']:
                del OTP_STORAGE[phone]
                return jsonify({
                    "data": None,
                    "status": 500,
                    "message": "تم تجاوز الحد الأقصى للمحاولات"
                }), 500

            return jsonify({
                "data": None,
                "status": 500,
                "message": "كلمة السر لمرة واحدة خاطئة ."
            }), 500

        # OTP is valid - generate tokens
        jwt_token = generate_jwt_token(phone)
        hmac_key = generate_hmac_key(phone)
        
        # Clear OTP after successful login
        del OTP_STORAGE[phone]
        
        logger.info(f"User logged in: {phone}")
        
        return jsonify({
            "data": {
                "token": jwt_token,
                "key": hmac_key
            },
            "status": 200,
            "message": "تم التحقق من المستخدم."
        }), 200
    
    except Exception as e:
        logger.error(f"Error in login_with_otp: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500





@app.route('/cmt/chatbot/getComplaintFields', methods=['POST'])
def get_complaint_fields():
    """
    Get complaint fields endpoint
    
    Request Body:
    {
        "sector": "Telecom"  # Possible values: 'Telecom', 'Post'
    }
    
    Responses:
    - Success: Complaint fields for specified sector (status 200)
    - Failure: Error in retrieving fields (status 500)
    """
    try:
        # Parse request data
        data = request.get_json()
        sector = data.get('sector', 'Telecom')
        
        # Determine language from header (default to Arabic)
        language = request.headers.get('Accept-Language', 'ar')

        # Complaint fields data structure
        if sector == 'Telecom':
            complaint_data = get_telecom_complaint_fields(language)
        elif sector == 'Post':
            complaint_data = get_post_complaint_fields(language)
        else:
            return jsonify({
                "data": None,
                "status": 500,
                "message": "Invalid sector specified"
            }), 500

        return jsonify({
            "data": complaint_data,
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

def get_telecom_complaint_fields(language='ar'):
    """
    Retrieve Telecom complaint fields based on language
    
    Args:
        language (str): Language code ('ar' or 'en')
    
    Returns:
        dict: Complaint fields data
    """
    if language == 'ar':
        return {
            "complainProviders": [
                {"code": "20", "value": "الشركة العمانية للاتصالات ( عمانتل)"},
                {"code": "21", "value": "الشركة العمانية القطرية للاتصالات ( اوريدو )"},
                # Add other providers from the specification
            ],
            "serviceTypes": [
                {
                    "code": "TF",
                    "value": "هاتف ثابت",
                    "subType": [
                        {"code": "1", "value": "ADSL"},
                        {"code": "2", "value": "الجيل الخامس"},
                        {"code": "3", "value": "الجيل الرابع"},
                        {"code": "4", "value": "الالياف البصرية"},
                        {"code": "5", "value": "آفاق"},
                        {"code": "6", "value": "الخطوط المؤجرة"}
                    ]
                },
                {
                    "code": "TM",
                    "value": "اتصالات متنقلة",
                    "subType": [
                        {"code": "7", "value": "الدفع الآجل- موبايل"},
                        {"code": "8", "value": "الدفع المسبق - موبايل"}
                    ]
                }
            ],
            "customerTypes": [
                {"code": "C", "value": "تجاري"},
                {"code": "I", "value": "فرد"},
                {"code": "N", "value": "غير محدد"}
            ],
            "complainTypes": [
                {"code": "1", "value": "فواتير", "locationRequired": False},
                {"code": "2", "value": "ضعف و إنقطاع في شبكة الإنترنت", "locationRequired": True},
                {"code": "3", "value": "عدم إضافة نقاط المكاسب", "locationRequired": False},
                {"code": "4", "value": "تفعيل الارقام", "locationRequired": False}
            ]
        }
    else:  # English
        return {
            "complainProviders": [
                {"code": "20", "value": "Oman Telecommunications Company (Omantel)"},
                {"code": "21", "value": "Omani Qatari Telecommunications Company (Ooredoo)"},
                # Add other providers from the specification
            ],
            "serviceTypes": [
                {
                    "code": "TF",
                    "value": "Telecom Fixed",
                    "subType": [
                        {"code": "1", "value": "ADSL"},
                        {"code": "2", "value": "5G"},
                        {"code": "3", "value": "4G"},
                        {"code": "4", "value": "Fiber"},
                        {"code": "5", "value": "Afaq"},
                        {"code": "6", "value": "Lease Line"}
                    ]
                },
                {
                    "code": "TM",
                    "value": "Telecom Mobile",
                    "subType": [
                        {"code": "7", "value": "Postpaid- Mobile"},
                        {"code": "8", "value": "Prepaid- Mobile"}
                    ]
                }
            ],
            "customerTypes": [
                {"code": "C", "value": "Corporate"},
                {"code": "I", "value": "Individual"},
                {"code": "N", "value": "Not Specified"}
            ],
            "complainTypes": [
                {"code": "1", "value": "Billing & payment", "locationRequired": False},
                {"code": "2", "value": "Quality of service", "locationRequired": True},
                {"code": "3", "value": "Promotional offers", "locationRequired": False},
                {"code": "4", "value": "Numbering", "locationRequired": False}
            ]
        }

def get_post_complaint_fields(language='ar'):
    """
    Placeholder for Post sector complaint fields
    
    Args:
        language (str): Language code ('ar' or 'en')
    
    Returns:
        dict: Placeholder post complaint fields
    """
    # Implement Post sector complaint fields similar to Telecom
    return {}



@app.route('/chatbot/raiseNewRequest', methods=['POST'])
def raise_new_request():
    """
    Raise a new request endpoint
    
    Request Body:
    Full request object as specified in the original document
    
    Responses:
    - Success: Request raised (status 200)
    - Failure: Validation errors (status 400)
    """
    try:
        # Parse request data
        data = request.get_json()
        
        # Validate required fields
        errors = validate_new_request(data)
        if errors:
            return jsonify({
                "data": None,
                "status": 400,
                "message": errors
            }), 400

        # Process file uploads (if any)
        if 'files' in data:
            process_request_files(data['files'])

        # Log the request (in a real scenario, would save to database)
        logger.info(f"New request raised: {data.get('customerName', 'Unknown')}")
        
        return jsonify({
            "data": None,
            "status": 200,
            "message": "شكرا ، سيتم النظر في الطلب المقدم ، وسيتم التواصل معك"
        }), 200
    
    except Exception as e:
        logger.error(f"Error in raise_new_request: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

def validate_new_request(data):
    """
    Validate new request data
    
    Args:
        data (dict): Request data to validate
    
    Returns:
        str: Error message or None if valid
    """
    # Validate phone number
    if not validate_phone(data.get('mobile', '')):
        return "Max Length of Phone number 8 / 13"

    # Validate email
    if not validate_email(data.get('email', '')):
        return "الرجاء تعبئة البريد الإلكتروني ببريد صحيح."

    # Validate required fields
    required_fields = [
        'customerName', 
        'provider', 
        'requestRequestType', 
        'requestServiceType'
    ]
    
    for field in required_fields:
        if not data.get(field):
            return f"Missing required field: {field}"

    return None

def process_request_files(files):
    """
    Process uploaded files for the request
    
    Args:
        files (list): List of file objects
    
    Returns:
        None
    """
    for file in files:
        # Extract file name and content
        file_name = file.get('fileName')
        file_content = file.get('fileContent')
        
        # Validate file
        if not file_name or not file_content:
            logger.warning(f"Invalid file: {file}")
            continue
        
        # In a real scenario:
        # 1. Decode base64 content
        # 2. Save to file system or cloud storage
        # 3. Store file reference in database
        # try:
        #     decoded_content = base64.b64decode(file_content)
        #     logger.info(f"Processed file: {file_name}, Size: {len(decoded_content)} bytes")
        # except Exception as e:
        #     logger.error(f"Error processing file {file_name}: {e}")



@app.route('/chatbot/raiseNewComplain', methods=['POST'])
def raise_new_complain():
    """
    Raise a new complaint endpoint
    
    Request Body:
    Full complaint object as specified in the original document
    
    Responses:
    - Success: Complaint raised (status 200)
    - Failure: Validation errors (status 400)
    """
    try:
        # Parse request data
        data = request.get_json()
        
        # Validate required fields
        errors = validate_new_complain(data)
        if errors:
            return jsonify({
                "data": None,
                "status": 400,
                "message": errors
            }), 400

        # Process file uploads (if any)
        if 'files' in data:
            process_complain_files(data['files'])

        # Log the complaint (in a real scenario, would save to database)
        logger.info(f"New complaint raised: {data.get('name', 'Unknown')}")
        
        return jsonify({
            "data": None,
            "status": 200,
            "message": "شكرا ، سيتم النظر في الطلب المقدم ، وسيتم التواصل معك"
        }), 200
    
    except Exception as e:
        logger.error(f"Error in raise_new_complain: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

def validate_new_complain(data):
    """
    Validate new complaint data
    
    Args:
        data (dict): Complaint data to validate
    
    Returns:
        str: Error message or None if valid
    """
    # Validate phone number
    if not validate_phone(data.get('contactPhone', '')):
        return "Max Length of Phone number 8 / 13"

    # Validate email
    if not validate_email(data.get('email', '')):
        return "الرجاء تعبئة البريد الإلكتروني ببريد صحيح."

    # Validate required fields
    required_fields = [
        'name', 
        'contactPhone', 
        'email', 
        'provider', 
        'serviceType', 
        'complainTypeDesc'
    ]
    
    for field in required_fields:
        if not data.get(field):
            return f"Missing required field: {field}"

    return None

def process_complain_files(files):
    """
    Process uploaded files for the complaint
    
    Args:
        files (list): List of file objects
    
    Returns:
        None
    """
    for file in files:
        # Extract file name and content
        file_name = file.get('fileName')
        file_content = file.get('fileContent')
        
        # Validate file
        if not file_name or not file_content:
            logger.warning(f"Invalid file: {file}")
            continue
        
        # In a real scenario:
        # 1. Decode base64 content
        # 2. Save to file system or cloud storage
        # # 3. Store file reference in database
        # try:
        #     decoded_content = base64.b64decode(file_content)
        #     logger.info(f"Processed complaint file: {file_name}, Size: {len(decoded_content)} bytes")
        # except Exception as e:
        #     logger.error(f"Error processing complaint file {file_name}: {e}")





@app.route('/cmt/chatbot/getRequestFields', methods=['GET'])
def get_request_fields():
    """
    Get request fields endpoint
    
    Query Parameters:
    - sector: Sector type (optional, default: 'Telecom')
    
    Request Headers:
    - Accept-Language: Language preference (optional, default: 'ar')
    
    Responses:
    - Success: Request fields for specified sector (status 200)
    - Failure: Error in retrieving fields (status 500)
    """
    try:
        # Get sector from query parameters
        sector = request.args.get('sector', 'Telecom')
        
        # Determine language from header (default to Arabic)
        language = request.headers.get('Accept-Language', 'ar')

        # Request fields data structure
        if sector == 'Telecom':
            request_data = get_telecom_request_fields(language)
        elif sector == 'Post':
            request_data = get_post_request_fields(language)
        else:
            return jsonify({
                "data": None,
                "status": 500,
                "message": "Invalid sector specified"
            }), 500

        return jsonify({
            "data": request_data,
            "status": 200,
            "message": ""
        }), 200
    
    except Exception as e:
        logger.error(f"Error in get_request_fields: {e}")
        return jsonify({
            "data": None,
            "status": 500,
            "message": str(e)
        }), 500

def get_telecom_request_fields(language='ar'):
    """
    Retrieve Telecom request fields based on language
    
    Args:
        language (str): Language code ('ar' or 'en')
    
    Returns:
        dict: Request fields data
    """
    if language == 'ar':
        return {
            "providers": [
                {"code": "20", "value": "الشركة العمانية للاتصالات ( عمانتل)"},
                {"code": "21", "value": "الشركة العمانية القطرية للاتصالات ( اوريدو )"}
            ],
            "requestTypes": [
                {
                    "code": "M",
                    "value": "طلب تعديل",
                    "serviceTypes": [
                        {"code": "1", "value": "خدمات الإنترنت"},
                        {"code": "2", "value": "خدمات الهاتف الثابت"},
                        {"code": "3", "value": "الخدمات المتنقلة"}
                    ]
                },
                {
                    "code": "N",
                    "value": "طلب جديد",
                    "serviceTypes": [
                        {"code": "1", "value": "خدمات الإنترنت"},
                        {"code": "2", "value": "خدمات الهاتف الثابت"},
                        {"code": "3", "value": "الخدمات المتنقلة"}
                    ]
                }
            ],
            "customerTypes": [
                {"code": "C", "value": "تجاري"},
                {"code": "I", "value": "فردي"},
                {"code": "N", "value": "غير محدد"}
            ]
        }
    else:  # English
        return {
            "providers": [
                {"code": "20", "value": "Oman Telecommunications Company (Omantel)"},
                {"code": "21", "value": "Omani Qatari Telecommunications Company (Ooredoo)"}
            ],
            "requestTypes": [
                {
                    "code": "M",
                    "value": "Modification Request",
                    "serviceTypes": [
                        {"code": "1", "value": "Internet Services"},
                        {"code": "2", "value": "Fixed Line Services"},
                        {"code": "3", "value": "Mobile Services"}
                    ]
                },
                {
                    "code": "N",
                    "value": "New Request",
                    "serviceTypes": [
                        {"code": "1", "value": "Internet Services"},
                        {"code": "2", "value": "Fixed Line Services"},
                        {"code": "3", "value": "Mobile Services"}
                    ]
                }
            ],
            "customerTypes": [
                {"code": "C", "value": "Corporate"},
                {"code": "I", "value": "Individual"},
                {"code": "N", "value": "Not Specified"}
            ]
        }

def get_post_request_fields(language='ar'):
    """
    Placeholder for Post sector request fields
    
    Args:
        language (str): Language code ('ar' or 'en')
    
    Returns:
        dict: Placeholder post request fields
    """
    # Implement Post sector request fields similar to Telecom
    return {}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
