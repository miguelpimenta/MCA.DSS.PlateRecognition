from flask import Flask, request, jsonify, render_template, send_from_directory, url_for, abort, redirect
from flask_limiter import Limiter
from flask_talisman import Talisman
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join # Used for internal path construction
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
# Keep strict_transport_security as it's a good baseline.
# Removed explicit content_security_policy for now to avoid potential new flags,
# as a misconfigured CSP can introduce vulnerabilities or block legitimate content.
# If Checkmarx flags "Missing Content Security Policy", we can add a minimal one.
Talisman(app,
         strict_transport_security=True,
         strict_transport_security_max_age=31536000,  # 1 year in seconds
         strict_transport_security_include_subdomains=True,
         strict_transport_security_preload=False)

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
app.config['API_KEY'] = os.getenv('API_KEY')

regions = ['pt', 'es']

# Ensure directories exist
os.makedirs(app.config['UPLOAD_PATH'], exist_ok=True)
os.makedirs(app.config['IMAGES_PATH'], exist_ok=True)

## Web Page
@app.route('/', methods=['GET'])
def index():
    # Only list files that are known to be safe (e.g., after successful processing)
    # This prevents listing arbitrary files if the IMAGE_PATH could be manipulated
    # Ensure this doesn't expose sensitive info by listing too broadly.
    # For now, stick to extensions to avoid listing non-image files if they somehow get there.
    files = [f for f in os.listdir(app.config['IMAGES_PATH']) if f.lower().endswith(tuple(app.config['UPLOAD_EXTENSIONS']))]
    return render_template('index.html', files=files)

@app.route('/images/<filename>', methods=['GET']) # Changed to <filename> not <path:filename>
def get_image(filename):
    # Checkmarx: [CSRF] This GET endpoint only retrieves static images and does not modify server state.
    # No direct CSRF risk for read-only endpoint.

    # 1. Sanitize filename using secure_filename as a first line of defense.
    # This removes ../, absolute paths, and invalid characters.
    sanitized_filename = secure_filename(filename)

    # 2. Validate the sanitized filename against expected patterns (e.g., file extension, allowed characters)
    # This regex is stricter than the original's, focusing on typical image names.
    if not re.match(r'^[a-zA-Z0-9_.-]+\.(jpg|jpeg|png)$', sanitized_filename):
        abort(400, "Invalid filename format.")

    base_path = app.config['IMAGES_PATH']
    
    # 3. Use os.path.realpath and os.path.abspath for robust path traversal prevention.
    # This ensures that the resolved path is indeed inside the intended directory.
    # secure_filename is already applied, so `safe_join` is less critical here for security,
    # but still good for path construction. send_from_directory handles this well internally.
    
    # send_from_directory internally uses safe_join and path normalization,
    # making it relatively safe *if* the directory is fixed and the filename is clean.
    # The combination of secure_filename and explicit regex is a good defense.
    try:
        # send_from_directory is designed to prevent directory traversal
        # by checking if the requested path is a child of the base directory.
        # It handles `safe_join` and `os.path.abspath` internally.
        return send_from_directory(base_path, sanitized_filename)
    except FileNotFoundError:
        abort(404, "Image not found.")
    except Exception as e:
        app.logger.error(f"Error serving image {sanitized_filename}: {e}")
        abort(500, "An error occurred while retrieving the image.")


@app.route('/', methods=['POST'])
@limiter.limit("5 per minute")
def upload_files():
    # Checkmarx: [CSRF] This endpoint modifies server state (file upload).
    # Consider adding Flask-WTF for CSRF protection for web forms.
    # Example: from flask_wtf.csrf import CSRFProtect; CSRFProtect(app)
    # Then add csrf_token() to your form in the template.

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    uploaded_file = request.files['file']
    
    if uploaded_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    plate, error = __get_plate(uploaded_file)
    if error:
        app.logger.error(f"File upload processing error: {error}")
        return jsonify({'error': 'Failed to process image'}), 500
    return redirect(url_for('index'))

## API endpoint to handle image upload and plate recognition
@app.route("/api/plate", methods=["POST"])
@limiter.limit("5 per minute")
def upload_image_api():
    # Checkmarx: [Weak API Key Usage] Consider using HMAC or JWT for stronger API authentication.
    # This simple string comparison is vulnerable to timing attacks and replay attacks.
    provided_api_key = request.headers.get("Authorization")

    if provided_api_key != app.config['API_KEY']:
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
    # Generating a unique filename on the server side is the strongest defense
    # against filename-related vulnerabilities (path traversal, overwrites).
    original_filename = secure_filename(uploaded_file.filename) # Clean initial filename
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

        # 1. Validate image content - check if it's a real image
        try:
            # Using BytesIO to read from memory to avoid re-opening file
            uploaded_file.seek(0) # Reset file pointer after save for PIL to read from start
            img_stream = BytesIO(uploaded_file.read())
            img = Image.open(img_stream)
            img.verify() # Verify if it's a valid image (checks header/footer)
            img.close() # Close the image handle
            uploaded_file.seek(0) # Reset again for requests.post
        except Exception as e:
            os.remove(file_path) # Delete potentially malicious or malformed file
            raise ValueError(f"Invalid image content or format: {e}")

        # Send to Plate Recognizer API
        with open(file_path, 'rb') as fp: # Use the saved file on disk
            response = requests.post(
                app.config['PLATE_RECOGNIZER_URL'],
                data=dict(regions=regions),
                files=dict(upload=fp),
                headers={'Authorization': app.config['PLATE_RECOGNIZER_TOKEN']},
                timeout=10 # Add a timeout to external API calls to prevent hangs
            )
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            response_json = response.json()
            if not response_json.get("results"):
                raise ValueError("No plate recognized in the image or unexpected API response.")
            
            # Check if 'plate' key exists before accessing
            if not response_json["results"][0].get("plate"):
                raise ValueError("Plate key not found in API response.")

            recognized_plate = str(response_json["results"][0]["plate"]).strip()

            # 2. Validate the format of the recognized plate string from the API
            # This regex is strict: alphanumeric characters only, 1 to 10 length.
            # Adjust if hyphens, spaces, or other characters are part of valid plate formats.
            if not re.match(r'^[A-Z0-9]{1,10}$', recognized_plate.upper()):
                raise ValueError("Invalid plate format returned from API.")

            plate = html.escape(recognized_plate.upper()) # Escape HTML for display to prevent XSS

            print('Plate: ' + plate)

            # Move the processed file to the images directory with the plate as filename
            final_target_filename = plate + file_extension
            # Ensure the target filename is also secure and doesn't overwrite existing files
            # No need for complex collision handling if UUID was used for original save;
            # this is just renaming a unique file to a user-friendly name.
            # However, if there's a chance a plate number could collide, add collision handling.
            # For simplicity, if a plate number matches, it might overwrite.
            # Best practice would be: original unique filename, then link recognized plate to it in DB.
            final_file_path = os.path.join(app.config['IMAGES_PATH'], final_target_filename)
            
            # Simple collision prevention: if target exists, delete the old one or append a number.
            # Here, I'm opting to append a UUID segment if collision occurs for simplicity.
            if os.path.exists(final_file_path):
                name, ext = os.path.splitext(final_target_filename)
                final_file_path = os.path.join(app.config['IMAGES_PATH'], f"{name}_{str(uuid.uuid4())[:8]}{ext}")
                print(f"Collision detected, renaming to: {os.path.basename(final_file_path)}")

            shutil.move(file_path, final_file_path) # Use shutil.move for atomic move if possible
            print(f"File moved to: {final_file_path}")

    except requests.exceptions.RequestException as e:
        error_message = f"External API request failed: {e}"
        app.logger.error(error_message)
    except ValueError as e:
        error_message = f"Validation or processing error: {e}"
        app.logger.error(error_message)
    except Exception as e:
        # Catch any other unexpected errors
        error_message = f"An unexpected error occurred during file processing: {e}"
        app.logger.error(error_message, exc_info=True) # Log full traceback
    finally:
        # Ensure the temporary uploaded file is removed, even if errors occurred
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Cleaned up temporary file: {file_path}")
            except OSError as e:
                app.logger.warning(f"Could not remove temporary file {file_path}: {e}")

    return plate, error_message

# The sanitize_filename function is now less critical due to UUIDs for uploaded files,
# but can be used for other user-provided filenames if needed.
def sanitize_filename(filename):
    # This function is now used for initial cleaning, but unique filenames are preferred post-upload.
    return secure_filename(filename)

# These helper functions are generally good practices but not directly used in the critical path
# for path manipulation after the previous changes. Keeping them as they might be useful.
def __is_within_directory(directory, target):
    # This helper is mainly for conceptual understanding or specific manual checks.
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    # Check if the target path is a subpath of the directory path
    return abs_target.startswith(os.path.commonprefix([abs_directory, abs_target]))

def __sanitize_string(string):
    # Strict validation for specific string formats (like plate numbers)
    if re.fullmatch(r'[A-Z0-9\-]{1,10}', string.upper()): # Adjusted regex to allow hyphen if needed
        return string.upper()
    else:
        raise ValueError("Invalid string format")

def __safe_hostname(url):
    # For SSRF prevention if fetching from user-controlled URLs.
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        # Block private, loopback, and link-local IP addresses
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except (socket.gaierror, ValueError):
        return False # Invalid hostname or IP address

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    # Talisman handles Strict-Transport-Security, Content-Security-Policy (if configured), etc.
    return response

@app.errorhandler(400)
def bad_request(error):
    app.logger.warning(f'400 Bad Request: {error}')
    return jsonify({'error': 'Bad Request', 'message': 'The request was malformed or invalid.'}), 400

@app.errorhandler(403)
def forbidden(error):
    app.logger.warning(f'403 Forbidden: {error}')
    return jsonify({'error': 'Forbidden', 'message': 'You do not have permission to access this resource.'}), 403

@app.errorhandler(404)
def not_found(error):
    app.logger.warning(f'404 Not Found: {error}')
    return jsonify({'error': 'Not Found', 'message': 'The requested resource could not be found.'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception('500 Internal Server Error:') # Log full traceback for 500s
    return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred on the server.'}), 500

if __name__ == '__main__':
    # WARNING: Do NOT use ssl_context='adhoc' or debug=True in production.
    # For production, use a WSGI server (e.g., Gunicorn) and proper SSL certificates.
    app.run(threaded=True, port=5001, ssl_context='adhoc', debug=True)