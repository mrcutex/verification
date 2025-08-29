from flask import Flask, request, jsonify, render_template_string
import uuid
import time
import hashlib
import hmac
import json
import base64
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration
SECRET_KEY = "your-super-secret-key-change-in-production"
SESSIONS = {}  # In-memory storage for sessions

def generate_session_token():
    return str(uuid.uuid4())

def create_short_url(session_token):
    # Create a short identifier for the URL
    short_id = hashlib.md5(session_token.encode()).hexdigest()[:8]
    return short_id

def sign_jwt_token(device_hash):
    # Simple JWT-like token creation
    payload = {
        "deviceHash": device_hash,
        "issuedAt": int(time.time()),
        "expiresAt": int(time.time()) + (24 * 60 * 60)  # 24 hours
    }
    
    # Create signature
    payload_str = json.dumps(payload, sort_keys=True)
    signature = hmac.new(
        SECRET_KEY.encode(),
        payload_str.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Combine payload and signature
    token_data = {
        "payload": payload,
        "signature": signature
    }
    
    # Base64 encode the token
    token_json = json.dumps(token_data)
    token = base64.b64encode(token_json.encode()).decode()
    
    return token

def verify_jwt_token(token):
    try:
        # Decode the token
        token_json = base64.b64decode(token.encode()).decode()
        token_data = json.loads(token_json)
        
        payload = token_data["payload"]
        signature = token_data["signature"]
        
        # Verify signature
        payload_str = json.dumps(payload, sort_keys=True)
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if signature != expected_signature:
            return False
        
        # Check expiration
        if int(time.time()) > payload["expiresAt"]:
            return False
            
        return True
    except:
        return False

@app.route('/getShortLink', methods=['GET'])
def get_short_link():
    session_token = generate_session_token()
    short_id = create_short_url(session_token)
    
    # Store session
    SESSIONS[session_token] = {
        "shortId": short_id,
        "createdAt": time.time(),
        "verified": False
    }
    
    # Clean old sessions (older than 1 hour)
    current_time = time.time()
    expired_sessions = [token for token, data in SESSIONS.items() 
                       if current_time - data["createdAt"] > 3600]
    for token in expired_sessions:
        del SESSIONS[token]
    
    base_url = request.url_root.rstrip('/')
    short_url = f"{base_url}/verify/{short_id}"
    
    return jsonify({
        "success": True,
        "sessionToken": session_token,
        "shortUrl": short_url
    })

@app.route('/verify/<short_id>', methods=['GET'])
def verify_page(short_id):
    # Find session by short_id
    session_token = None
    for token, data in SESSIONS.items():
        if data["shortId"] == short_id:
            session_token = token
            break
    
    if not session_token:
        return "Invalid or expired verification link", 404
    
    # HTML page with deeplink button
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Device Verification</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.2);
                text-align: center;
                max-width: 400px;
                width: 100%;
            }
            .icon {
                font-size: 48px;
                margin-bottom: 20px;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 24px;
            }
            p {
                color: #666;
                margin-bottom: 30px;
                line-height: 1.5;
            }
            .verify-btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 16px 32px;
                font-size: 16px;
                border-radius: 8px;
                cursor: pointer;
                transition: transform 0.2s;
                font-weight: 600;
                width: 100%;
                margin-bottom: 15px;
            }
            .verify-btn:hover {
                transform: translateY(-2px);
            }
            .verify-btn:active {
                transform: translateY(0);
            }
            .cancel-btn {
                background: transparent;
                color: #666;
                border: 1px solid #ddd;
                padding: 12px 32px;
                font-size: 14px;
                border-radius: 8px;
                cursor: pointer;
                width: 100%;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">🔐</div>
            <h1>Device Verification</h1>
            <p>Complete your device verification by returning to the app.</p>
            
            <button class="verify-btn" onclick="openApp()">
                Return to App
            </button>
            
            <button class="cancel-btn" onclick="window.close()">
                Cancel
            </button>
        </div>
        
        <script>
            function openApp() {
                const deeplink = 'myapp://readyForVerify?sessionToken={{ session_token }}';
                window.location.href = deeplink;
                
                // Fallback: close window after 3 seconds if app doesn't open
                setTimeout(function() {
                    window.close();
                }, 3000);
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html_template, session_token=session_token)

@app.route('/verifyDevice', methods=['POST'])
def verify_device():
    data = request.get_json()
    
    if not data or 'sessionToken' not in data or 'deviceHash' not in data:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    
    session_token = data['sessionToken']
    device_hash = data['deviceHash']
    
    # Check if session exists
    if session_token not in SESSIONS:
        return jsonify({"success": False, "error": "Invalid session token"}), 401
    
    session_data = SESSIONS[session_token]
    
    # Check if session is not too old (max 1 hour)
    if time.time() - session_data["createdAt"] > 3600:
        del SESSIONS[session_token]
        return jsonify({"success": False, "error": "Session expired"}), 401
    
    # Mark session as verified
    SESSIONS[session_token]["verified"] = True
    SESSIONS[session_token]["deviceHash"] = device_hash
    
    # Create signed token
    signed_token = sign_jwt_token(device_hash)
    
    # Calculate next verification time (24 hours from now)
    next_verify_at = int(time.time()) + (24 * 60 * 60)
    
    # Clean up session (optional)
    # del SESSIONS[session_token]
    
    return jsonify({
        "success": True,
        "signedToken": signed_token,
        "nextVerifyAt": next_verify_at,
        "message": "Device verified successfully"
    })

@app.route('/validateToken', methods=['POST'])
def validate_token():
    data = request.get_json()
    
    if not data or 'token' not in data:
        return jsonify({"success": False, "error": "Missing token"}), 400
    
    token = data['token']
    is_valid = verify_jwt_token(token)
    
    return jsonify({
        "success": True,
        "valid": is_valid
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "success": True,
        "message": "Server is running",
        "timestamp": int(time.time())
    })

if __name__ == '__main__':
    print("🚀 Device Verification Server Starting...")
    print("📱 Use ngrok to expose this server: ngrok http 5000")
    print("🔧 Remember to update SERVER_BASE in Android app with ngrok URL")
    app.run(host='0.0.0.0', port=5000, debug=True)
