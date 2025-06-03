from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, abort, redirect
from werkzeug.utils import secure_filename
import requests
import json
import os
import hmac
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOAD_PATH'] = 'uploads'
app.config['PLATE_RECOGNIZER_URL'] = os.getenv('PLATE_RECOGNIZER_URL')
app.config['PLATE_RECOGNIZER_TOKEN'] = os.getenv('PLATE_RECOGNIZER_TOKEN')
app.config['API_KEY'] = os.getenv('API_KEY')

regions = ['pt', 'es'] 

@app.route('/', methods=['GET'])
def index():
    files = os.listdir(app.config['UPLOAD_PATH'])
    return render_template('index.html', files=files)

@app.route('/uploads/<filename>', methods=['GET'])
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_PATH'], filename)

@app.route('/', methods=['POST'])
def upload_files():  
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400 
    uploaded_file = request.files['file'] 
    plate, error = __get_plate(uploaded_file)
    if error:
        return jsonify({'error': error}), 500
    return redirect(url_for('index'))

@app.route("/api/plate", methods=["POST"])
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
    filename = secure_filename(uploaded_file.filename)
    
    if filename != '':

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

        json_response = json.loads(json.dumps(response.json()))
        plate = json_response["results"][0]["plate"]

        print('Plate: ' + plate.upper())        
        fp.close()
        
        try: 
            os.rename(file_path, os.path.join(app.config['UPLOAD_PATH'], plate.upper() + file_ext))        
        except Exception as e:
            os.remove(os.path.join(app.config['UPLOAD_PATH'], plate.upper() + file_ext))
            os.rename(file_path, os.path.join(app.config['UPLOAD_PATH'], plate.upper() + file_ext))        
          
        return plate, e

if __name__ == '__main__':    
    app.run(threaded=True, port=5001)    