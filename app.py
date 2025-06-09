from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, abort, redirect
from flask_limiter import Limiter
from flask_talisman import Talisman
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join
from io import BytesIO
from PIL import Image
import html
import io
import requests
import json
import os
import hmac
import uuid
import re
import socket, ipaddress
import shutil
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
#Talisman(app, strict_transport_security=True,
#        strict_transport_security_max_age=31536000, # 1 year in seconds
#        strict_transport_security_include_subdomains=True,
#        strict_transport_security_preload=False)

#limiter = Limiter(
#    get_remote_address,
#    app=app,
#    default_limits=["5000 per day", "50 per hour"],
#    storage_uri="memory://"
#)

app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.jpeg']
app.config['IMAGES_PATH'] = 'public/images'
app.config['UPLOAD_PATH'] = 'public/uploads'
app.config['PLATE_RECOGNIZER_URL'] = 'https://api.platerecognizer.com/v1/plate-reader/'
app.config['PLATE_RECOGNIZER_TOKEN'] = os.getenv('PLATE_RECOGNIZER_TOKEN')
app.config['API_KEY'] = os.getenv('API_KEY')
file_extension = '.jpg'  # Default file extension for images

regions = ['pt', 'es'] 

os.makedirs(app.config['UPLOAD_PATH'], exist_ok=True)
os.makedirs(app.config['IMAGES_PATH'], exist_ok=True)

## Web Page
@app.route('/', methods=['GET'])
def index():
    files = os.listdir(app.config['IMAGES_PATH'])
    return render_template('index.html', files=files)

@app.route('/images/', methods=['GET'])
def get_image():
    filename = html.escape(request.args.get('filename', ''))

    if not re.match(r'^[a-zA-Z0-9_.-]+\.(jpg|jpeg)$', filename):
        abort(400)

    base_path = app.config['IMAGES_PATH']
    requested_path = os.path.join(base_path, filename)
    
    absolute_requested_path = os.path.abspath(requested_path)
    real_requested_path = os.path.realpath(absolute_requested_path)
    real_base_path = os.path.realpath(base_path)

    if not real_requested_path.startswith(real_base_path):
        abort(403, "Access denied")
    
    if not os.path.exists(real_requested_path):
        abort(404)

    return send_from_directory(app.config['IMAGES_PATH'], filename)

@app.route('/', methods=['POST'])
def upload_files():  
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400 
    
    uploaded_file = request.files['file']    
    image_bytes = uploaded_file.read()
    
    plate, error = __get_plate(image_bytes)
    if error:
        abort(500)
    return redirect(url_for('index'))

## API endpoint to handle image upload and plate recognition
@app.route("/api/plate", methods=["POST"])
#@limiter.limit("2000 per minute")
def upload_image():
    authorization = request.headers.get("Authorization")

    if authorization != (app.config['API_KEY']):
        return jsonify({'result': '403 Forbidden'}), 403
    else:        
        uploaded_file = request.files['file']         
        image_bytes = uploaded_file.read()        
        plate, error = __get_plate(image_bytes)
        
        if error:
            abort(500)
        message = {
            'plate': plate
        }
        return jsonify(message), 200           

###
def __get_plate(image_bytes):    

    unique_id = str(uuid.uuid4())
    temp_filename = f"{unique_id}.jpg"  # Use a unique filename to avoid conflicts

    if not image_bytes:
        return None, "Image bytes are empty or could not be read."
    file_path = os.path.join(app.config['UPLOAD_PATH'], temp_filename)

    plate = None
    error_message = None
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.save(file_path)         
    
        with open(file_path, 'rb') as fp:
            response = requests.post(
                app.config['PLATE_RECOGNIZER_URL'],
                data=dict(regions=regions),
                files=dict(upload=fp),
                headers={'Authorization': app.config['PLATE_RECOGNIZER_TOKEN']}
            )       
            response.raise_for_status()
                    
            if not re.match(r'^[A-Za-z0-9]+$', response.json()["results"][0]["plate"]):
                raise ValueError("Invalid format!")
            
            plate = html.escape(response.json()["results"][0]["plate"])
            plate = plate.upper()
            
            print('Plate: ' + plate)

            final_filename = f"{plate}{file_extension}"
            final_file_path = os.path.join(app.config['IMAGES_PATH'], final_filename)           
            
            # Ensure we don't overwrite existing files
            counter = 1
            while os.path.exists(final_file_path):
                final_filename = f"{plate}_{counter}{file_extension}"
                final_file_path = os.path.join(app.config['IMAGES_PATH'], final_filename)
                counter += 1            
            shutil.copy(file_path, final_file_path)            
            
    except Exception as e:
        print(str(e))
        error_message = "Internal Server Error..."
            
    finally:
        # remove temp file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Cleaned up temporary file: {file_path}")
            except OSError as e:
                print(f"Warning: Could not remove temporary file {file_path}: {e}")
          
    return plate, error_message

def sanitize_filename(filename):
    # Remove directory traversal attempts
    filename = os.path.basename(filename)    
    # Remove null bytes and other dangerous characters
    filename = filename.replace('\0', '')    
    # Replace path separators and other dangerous chars
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')    
    print(f"Sanitized filename: {filename}")
    return secure_filename(filename)
    
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    #response.headers['X-Frame-Options'] = 'DENY'
    response.headers.pop('X-Frame-Options', None)
    return response

@app.errorhandler(400)
def bad_request(error):
    print('error: ' + str(error)) 
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(403)
def forbidden():    
    print('error: ' + str(error)) 
    return jsonify({'error': 'Forbidden'}), 403

if __name__ == '__main__':    
    app.run(threaded=True, port=5001) #, ssl_context='adhoc')    