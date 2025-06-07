from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, abort, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join
from io import BytesIO
from PIL import Image
import html
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

limiter = Limiter(get_remote_address, app=app)

app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['IMAGES_PATH'] = 'public/images'
app.config['UPLOAD_PATH'] = 'public/uploads'
app.config['PLATE_RECOGNIZER_URL'] = 'https://api.platerecognizer.com/v1/plate-reader/'
app.config['PLATE_RECOGNIZER_TOKEN'] = os.getenv('PLATE_RECOGNIZER_TOKEN')
app.config['API_KEY'] = os.getenv('API_KEY')

regions = ['pt', 'es'] 

## Web Page
@app.route('/', methods=['GET'])
def index():
    files = os.listdir(app.config['IMAGES_PATH'])
    return render_template('index.html', files=files)

@app.route('/images/<filename>', methods=['GET'])
def get_image(filename):
    file_name =  html.escape(filename)
    file_path = os.path.join(app.config['IMAGES_PATH'], file_name)    
    if not os.path.exists(file_path):
        abort(404)
    return send_from_directory(app.config['IMAGES_PATH'], file_name)

@app.route('/', methods=['POST'])
def upload_files():  
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400 
    uploaded_file = request.files['file'] 
    plate, error = __get_plate(uploaded_file)
    if error:
        return jsonify({'error': error}), 500
    return redirect(url_for('index'))

## API endpoint to handle image upload and plate recognition
@app.route("/api/plate", methods=["POST"])
@limiter.limit("5 per minute")
def upload_image():
    authorization = request.headers.get("Authorization")

    if authorization != (app.config['API_KEY']):
        return jsonify({'result': '403 Forbidden'}), 403
    else:        
        uploaded_file = request.files['file'] 
        plate = __get_plate(uploaded_file)    
        message = {
            'plate': plate
        }
        return jsonify(message), 200           

###
def __get_plate(uploaded_file):    
    filename = sanitize_filename(uploaded_file.filename)
    
    if filename == '':
        abort(400)

    file_path = os.path.join(app.config['UPLOAD_PATH'], filename)
    file_ext = os.path.splitext(filename)[1]

    if file_ext not in app.config['UPLOAD_EXTENSIONS']:
        abort(400)

    uploaded_file.save(file_path)      
    
    with open(file_path, 'rb') as fp:
        response = requests.post(
            app.config['PLATE_RECOGNIZER_URL'],
            data=dict(regions=regions),
            files=dict(upload=fp),
            headers={'Authorization': app.config['PLATE_RECOGNIZER_TOKEN']})       
                  
        if not re.match(r'^[A-Za-z0-9]+$', response.json()["results"][0]["plate"]):
            raise ValueError("Invalid format!")
        
        plate = html.escape(response.json()["results"][0]["plate"])

        print('Plate: ' + plate.upper())
        
        try: 
            os.rename(file_path, os.path.join(app.config['IMAGES_PATH'], plate.upper() + file_ext))
        except Exception as e:
            os.rename(file_path, os.path.join(app.config['UPLOAD_PATH'], plate.upper() + file_ext))
            os.remove(os.path.join(app.config['UPLOAD_PATH'], plate.upper() + file_ext))            
            return None, str(e)
          
        return plate, None
    
#def __is_within_directory(directory, target):
#    werkzeug.security.safe_join()
#    abs_directory = os.path.abspath(directory)
#    abs_target = os.path.abspath(target)
#    return os.path.commonprefix([abs_directory, abs_target]) == abs_directory

def sanitize_filename(filename):
    # Remove directory traversal attempts
    filename = os.path.basename(filename)    
    # Remove null bytes and other dangerous characters
    filename = filename.replace('\0', '')    
    # Replace path separators and other dangerous chars
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')    
    # Ensure filename isn't empty
    #if not filename:
        #filename = 'unnamed_file'    
    print(f"Sanitized filename: {filename}")
    return filename

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

def __is_within_directory(directory, target):
    safe_path = safe_join(directory, target)
    return safe_path is not None
    
def __sanitize_string(string):
    if re.fullmatch(r'[A-Z0-9\-]{1,10}', string.upper()):
        return string.upper()
    else:
        raise ValueError("Invalid string format")
    
def __safe_hostname(url):
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)

@app.errorhandler(400)
def bad_request(error):
    print('error: ' + str(error)) 
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(403)
def forbidden():    
    print('error: ' + str(error)) 
    return jsonify({'error': 'Forbidden'}), 403

if __name__ == '__main__':    
    app.run(threaded=True, port=5001)    