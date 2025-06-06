from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, abort, redirect
from werkzeug.utils import secure_filename
import requests
import json
import os
import hmac
import re
import socket, ipaddress
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOAD_PATH'] = 'uploads'
app.config['PLATE_RECOGNIZER_URL'] = 'https://api.platerecognizer.com/v1/plate-reader/'
app.config['PLATE_RECOGNIZER_TOKEN'] = os.getenv('PLATE_RECOGNIZER_TOKEN')
app.config['API_KEY'] = os.getenv('API_KEY')

regions = ['pt', 'es'] 

## Web Page
@app.route('/', methods=['GET'])
def index():
    files = os.listdir(app.config['UPLOAD_PATH'])
    return render_template('index.html', files=files)

@app.route('/uploads/<filename>', methods=['GET'])
def get_image(filename):
    safe_filename = secure_filename(filename)
    file_path = os.path.join(app.config['UPLOAD_PATH'], safe_filename)
    if not os.path.exists(file_path):
        abort(404)

    return send_from_directory(app.config['UPLOAD_PATH'], safe_filename)

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
def upload_image():

    authorization = request.headers.get("Authorization")

    if authorization != (app.config['API_KEY']):
        return jsonify({'result': '403 Forbidden'}), 403
    else:        
        uploaded_file = request.files['file']         
        filename = secure_filename(uploaded_file.filename)  # Get the filename

        if filename == '':
            abort(400, 'Empty filename')

        image_bytes = uploaded_file.read()

        plate = __get_plate(image_bytes, filename)

        if plate is None:
            return jsonify({'error': 'Plate recognition failed'}), 500
        message = {
            'plate': plate
        }
        return jsonify(message), 200        

###
def __get_plate(image_bytes: bytes, filename: str):
        
    file_ext = os.path.splitext(filename)[1]
    if file_ext not in app.config['UPLOAD_EXTENSIONS']:       
        abort(400, 'Invalid file extension')

    upload_dir = app.config['UPLOAD_PATH']
    file_path = os.path.join(upload_dir, filename)

    if not __is_within_directory(upload_dir, file_path):
        abort(400, 'Path traversal detected')

    image_bytes.save(file_path)

    PLATE_RECOGNIZER_URL = app.config['PLATE_RECOGNIZER_URL']
    if not __safe_hostname(PLATE_RECOGNIZER_URL):
        abort(403, 'Unsafe URL blocked by SSRF protection')

    with open(file_path, 'rb') as fp:
        response = requests.post(
            PLATE_RECOGNIZER_URL,
            data=dict(regions=regions),
            files=dict(upload=fp),
            headers={'Authorization': app.config['PLATE_RECOGNIZER_TOKEN']},
            allow_redirects=False
        )                    

        json_response = response.json()
        plate = __sanitize_string(json_response["results"][0]["plate"])

        # Debug...
        print('Plate: ' + plate.upper())        
        
        safe_new_name = secure_filename(plate.upper() + file_ext)
        new_path = os.path.join(app.config['UPLOAD_PATH'], safe_new_name)

        if not __is_within_directory(upload_dir, new_path):
            abort(400, 'Invalid rename path')

        try:
            os.rename(file_path, new_path)
        except FileExistsError:
            os.remove(new_path)
            os.rename(file_path, new_path)
        except Exception as e:
            return None, str(e)
          
        return plate, None
    
def __is_within_directory(directory, target):
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    return os.path.commonprefix([abs_directory, abs_target]) == abs_directory
    
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

if __name__ == '__main__':    
    app.run(threaded=True, port=5001)    