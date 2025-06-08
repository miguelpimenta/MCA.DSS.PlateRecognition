from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, abort, redirect
from flask_limiter import Limiter
from flask_talisman import Talisman
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

# Talisman for security headers
Talisman(app,
         strict_transport_security=True,
         strict_transport_security_max_age=31536000,  # 1 year in seconds
         strict_transport_security_include_subdomains=True,
         strict_transport_security_preload=False,
         content_security_policy={
             'default-src': ["'self'"],
             'img-src': ["'self'", "data:"], # Allow images from self and data URIs
             'style-src': ["'self'", "'unsafe-inline'"], # 'unsafe-inline' should be avoided if possible, but often needed for Flask's default CSS
             'script-src': ["'self'"],
             'object-src': ["'none'"]
         })

# Limiter for rate limiting
limiter = Limiter(get_remote_address,
                  app=app,
                  default_limits=["200 per day", "50 per hour"],
                  storage_uri="memory://",  # Consider a more persistent storage in production like Redis
                  strategy="fixed-window"
)

app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.jpeg', '.png']
app.config['IMAGES_PATH'] = 'public/images'
app.config['UPLOAD_PATH'] = 'public/uploads'
app.config['PLATE_RECOGNIZER_URL'] = 'https://api.platerecognizer.com/v1/plate-reader/'
app.config['PLATE_RECOGNIZER_TOKEN'] = os.getenv('PLATE_RECOGNIZER_TOKEN')
app.config['API_KEY'] = os.getenv('API_KEY') # It's generally better to use a proper API key management system

regions = ['pt', 'es']

# Ensure directories exist
os.makedirs(app.config['UPLOAD_PATH'], exist_ok=True)
os.makedirs(app.config['IMAGES_PATH'], exist_ok=True)

## Web Page
@app.route('/', methods=['GET'])
def index():
    # Only list files that are known to be safe (e.g., after successful processing)
    # This prevents listing arbitrary files if the IMAGE_PATH could be manipulated
    files = [f for f in os.listdir(app.config['IMAGES_PATH']) if f.endswith(tuple(app.config['UPLOAD_EXTENSIONS']))]
    return render_template('index.html', files=files)

@app.route('/images/<path:filename>', methods=['GET'])
def get_image(filename):
    # Checkmarx: Re-evaluate [CSRF] if this endpoint can trigger state changes indirectly.
    # Currently, it retrieves static images, so CSRF isn't a direct concern for this GET,
    # but the overall application flow should be considered.

    # Sanitize filename to prevent directory traversal and other path manipulations
    # using secure_filename is good, but combine it with other checks
    filename = secure_filename(filename)

    if not re.match(r'^[a-zA-Z0-9_.-]+\.(jpg|jpeg|png)$', filename):
        abort(400, "Invalid filename format")

    base_path = app.config['IMAGES_PATH']
    
    # Use safe_join to ensure the requested path is safely within the base directory
    requested_path = safe_join(base_path, filename)

    if requested_path is None:
        abort(400, "Invalid path")

    # Double check for path traversal using realpath
    # This is a robust check against various path manipulation techniques
    real_base_path = os.path.realpath(base_path)
    real_requested_path = os.path.realpath(requested_path)

    if not real_requested_path.startswith(real_base_path):
        abort(403, "Access denied: Path traversal detected")

    if not os.path.exists(real_requested_path):
        abort(404)

    return send_from_directory(app.config['IMAGES_PATH'], filename)

@app.route('/', methods=['POST'])
@limiter.limit("5 per minute") # Apply rate limiting to file uploads as well
def upload_files():
    # Consider adding CSRF protection here as this endpoint modifies server state (uploads files)
    # For a simple Flask app, you might use Flask-WTF and its CSRF protection.

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    plate, error = __get_plate(uploaded_file)
    if error:
        # Log the actual error for debugging, but return a generic message to the user
        app.logger.error(f"File upload processing error: {error}")
        return jsonify({'error': 'Failed to process image'}), 500
    return redirect(url_for('index'))

## API endpoint to handle image upload and plate recognition
@app.route("/api/plate", methods=["POST"])
@limiter.limit("5 per minute")
def upload_image_api():
    # Use HMAC or a token with better security properties instead of a plain API key in headers.
    # For a production API, implement proper authentication (e.g., JWT, OAuth).
    provided_api_key = request.headers.get("Authorization")

    if provided_api_key != app.config['API_KEY']: # This is still a simple comparison.
        return jsonify({'result': '403 Forbidden', 'message': 'Invalid API Key'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    plate, error = __get_plate(uploaded_file)
    if error:
        app.logger.error(f"API image processing error: {error}")
        return jsonify({'error': 'Failed to process image', 'details': error}), 500
    message = {
        'plate': plate
    }
    return jsonify(message), 200

def __get_plate(uploaded_file):
    # It's better to generate a unique filename on the server side
    # to prevent name collisions and potential overwrites.
    # Keep the original extension.
    original_filename = secure_filename(uploaded_file.filename)
    file_extension = os.path.splitext(original_filename)[1].lower()

    if file_extension not in app.config['UPLOAD_EXTENSIONS']:
        return None, "Invalid file extension"

    # Generate a unique filename using UUID
    unique_filename = str(uuid.uuid4()) + file_extension
    file_path = os.path.join(app.config['UPLOAD_PATH'], unique_filename)

    plate = None
    error_message = None
    try:
        # Save the uploaded file
        uploaded_file.save(file_path)

        # Validate image content - check if it's a real image and potentially resize/compress
        try:
            img = Image.open(file_path)
            img.verify() # Verify if it's a valid image
        except Exception as e:
            raise ValueError(f"Invalid image content: {e}")

        # Send to Plate Recognizer API
        with open(file_path, 'rb') as fp:
            response = requests.post(
                app.config['PLATE_RECOGNIZER_URL'],
                data=dict(regions=regions),
                files=dict(upload=fp),
                headers={'Authorization': app.config['PLATE_RECOGNIZER_TOKEN']},
                timeout=10 # Add a timeout to external API calls
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            response_json = response.json()
            if not response_json.get("results"):
                raise ValueError("No plate recognized in the image.")

            recognized_plate = response_json["results"][0]["plate"]

            # Validate the format of the recognized plate string
            # Checkmarx: Regex for plate validation needs to be strict
            if not re.match(r'^[A-Z0-9]{1,10}$', recognized_plate.upper()): # Adjust regex as per actual plate formats
                raise ValueError("Invalid plate format returned from API.")

            plate = html.escape(recognized_plate.upper()) # Escape HTML characters for display

            print('Plate: ' + plate)

            # Move the processed file to the images directory with the plate as filename
            final_file_path = os.path.join(app.config['IMAGES_PATH'], plate + file_extension)
            
            # Ensure the destination filename is also secure and doesn't overwrite existing files unintentionally
            if os.path.exists(final_file_path):
                # Handle collision: append a number or UUID to the filename
                base, ext = os.path.splitext(final_file_path)
                counter = 1
                while os.path.exists(f"{base}_{counter}{ext}"):
                    counter += 1
                final_file_path = f"{base}_{counter}{ext}"

            shutil.move(file_path, final_file_path) # Use shutil.move for atomic move if possible
            print(f"File moved to: {final_file_path}")

    except requests.exceptions.RequestException as e:
        error_message = f"API request failed: {e}"
        app.logger.error(error_message)
    except ValueError as e:
        error_message = f"Validation error: {e}"
        app.logger.error(error_message)
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        app.logger.error(error_message)
    finally:
        # Ensure the temporary uploaded file is removed
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Cleaned up temporary file: {file_path}")
            except OSError as e:
                app.logger.warning(f"Could not remove temporary file {file_path}: {e}")

    return plate, error_message

def sanitize_filename(filename):
    # This function is now less critical for security due to server-side unique filename generation,
    # but it's still good practice for initial client-provided filenames.
    filename = secure_filename(filename)
    return filename

# The following helper functions are good security practices and are kept.
def __is_within_directory(directory, target):
    # This function is somewhat redundant now with realpath and startswith checks
    # but can be kept for additional clarity or if future changes reintroduce its utility.
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    return abs_target.startswith(os.path.commonprefix([abs_directory, abs_target]))

def __sanitize_string(string):
    # This function is specific to __sanitize_string and should be used where a strict alphanumeric
    # and hyphen format is expected, like for plate numbers.
    if re.fullmatch(r'[A-Z0-9\-]{1,10}', string.upper()):
        return string.upper()
    else:
        raise ValueError("Invalid string format")

def __safe_hostname(url):
    # This function is for SSRF protection and is a good addition if your application
    # were to fetch content from user-provided URLs. Not directly used in the current code,
    # but useful to keep if such functionality might be added.
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False # No hostname, not safe
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except (socket.gaierror, ValueError):
        return False # Invalid hostname or IP address

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    # Talisman handles most of the other critical headers
    return response

@app.errorhandler(400)
def bad_request(error):
    # Ensure error messages are not too verbose and don't leak internal details
    print(f'Error 400: {error}') # Log the detailed error
    return jsonify({'error': 'Bad Request', 'message': 'The request could not be understood or was missing required parameters.'}), 400

@app.errorhandler(403)
def forbidden(error): # Add error argument to match errorhandler signature
    print(f'Error 403: {error}') # Log the detailed error
    return jsonify({'error': 'Forbidden', 'message': 'You do not have permission to access this resource.'}), 403

@app.errorhandler(404)
def not_found(error):
    print(f'Error 404: {error}')
    return jsonify({'error': 'Not Found', 'message': 'The requested resource was not found.'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    print(f'Error 500: {error}')
    return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred on the server.'}), 500

if __name__ == '__main__':
    # For production, do not use adhoc SSL context. Use a proper certificate.
    # Also, do not run with debug=True in production.
    app.run(threaded=True, port=5001, ssl_context='adhoc', debug=True)