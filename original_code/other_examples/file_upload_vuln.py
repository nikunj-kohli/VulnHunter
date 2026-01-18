"""
Insecure File Upload Example - Vulnerable Code
==============================================
This demonstrates file upload vulnerabilities.
"""

from flask import Flask, request, send_file, send_from_directory
import os
import mimetypes

app = Flask(__name__)

# VULNERABLE: Predictable upload directory
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# VULNERABLE: Overly permissive allowed extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

def allowed_file(filename):
    """
    VULNERABLE: Weak file extension check
    Can be bypassed with double extensions or null bytes
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload/basic', methods=['POST'])
def basic_upload():
    """
    VULNERABLE: Multiple file upload vulnerabilities
    - No file size limit
    - Weak extension checking
    - Arbitrary filename
    """
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    
    if file.filename == '':
        return {'error': 'No file selected'}, 400
    
    # VULNERABLE: Using user-supplied filename without sanitization
    filename = file.filename
    
    # VULNERABLE: Weak extension check (can be bypassed)
    if allowed_file(filename):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # VULNERABLE: No file size check
        # VULNERABLE: No virus scanning
        # VULNERABLE: Overwrites existing files
        file.save(filepath)
        
        return {
            'status': 'success',
            'filename': filename,
            'path': filepath,  # VULNERABLE: Exposing full path
            'url': f'/download/{filename}'
        }
    
    return {'error': 'File type not allowed'}, 400

@app.route('/upload/custom_name', methods=['POST'])
def custom_name_upload():
    """
    VULNERABLE: Path traversal through custom filename
    """
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    custom_name = request.form.get('custom_name', file.filename)
    
    # VULNERABLE: No sanitization of custom filename
    # Allows path traversal: ../../etc/passwd
    filepath = os.path.join(UPLOAD_FOLDER, custom_name)
    
    # VULNERABLE: Creates directories if they don't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    file.save(filepath)
    
    return {
        'status': 'success',
        'saved_as': custom_name,
        'full_path': filepath
    }

@app.route('/upload/no_check', methods=['POST'])
def no_check_upload():
    """
    VULNERABLE: No file type validation at all
    Allows uploading executable files, scripts, etc.
    """
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    filename = file.filename
    
    # VULNERABLE: No validation whatsoever
    # Can upload .php, .py, .exe, .sh files
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    return {
        'status': 'success',
        'filename': filename,
        'message': 'File uploaded without any validation'
    }

@app.route('/upload/metadata', methods=['POST'])
def metadata_upload():
    """
    VULNERABLE: Exposing file metadata and system information
    """
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    # VULNERABLE: Exposing detailed file metadata
    file_stats = os.stat(filepath)
    
    return {
        'status': 'success',
        'filename': filename,
        'size': file_stats.st_size,
        'created': file_stats.st_ctime,
        'modified': file_stats.st_mtime,
        'path': filepath,
        'inode': file_stats.st_ino,
        'permissions': oct(file_stats.st_mode)
    }

@app.route('/download/<path:filename>')
def download_file(filename):
    """
    VULNERABLE: Path traversal in file download
    Allows downloading arbitrary files from the system
    """
    # VULNERABLE: No path sanitization
    # Allows: /download/../../etc/passwd
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        return send_file(filepath)
    except Exception as e:
        # VULNERABLE: Information disclosure in error
        return {'error': str(e), 'attempted_path': filepath}, 404

@app.route('/serve/<path:filename>')
def serve_file(filename):
    """
    VULNERABLE: Serving files directly without validation
    Can execute uploaded scripts
    """
    # VULNERABLE: No content-type validation
    # If PHP/Python/etc is enabled, uploaded scripts could execute
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/list_files')
def list_files():
    """
    VULNERABLE: Exposing directory listing
    """
    # VULNERABLE: Exposing all uploaded files
    files = os.listdir(UPLOAD_FOLDER)
    
    file_info = []
    for f in files:
        filepath = os.path.join(UPLOAD_FOLDER, f)
        stats = os.stat(filepath)
        file_info.append({
            'name': f,
            'size': stats.st_size,
            'path': filepath,  # VULNERABLE: Full path disclosure
            'url': f'/download/{f}'
        })
    
    return {'files': file_info}

@app.route('/delete/<filename>')
def delete_file(filename):
    """
    VULNERABLE: File deletion without authentication
    """
    # VULNERABLE: No authentication or authorization
    # VULNERABLE: Path traversal possible
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    try:
        os.remove(filepath)
        return {'status': 'success', 'message': f'{filename} deleted'}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/upload/zip', methods=['POST'])
def zip_upload():
    """
    VULNERABLE: Zip bomb / Zip slip vulnerability
    """
    import zipfile
    
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    
    if not file.filename.endswith('.zip'):
        return {'error': 'Only ZIP files allowed'}, 400
    
    zip_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(zip_path)
    
    # VULNERABLE: No size check (zip bomb)
    # VULNERABLE: No path validation (zip slip)
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # VULNERABLE: Extracts to user-controlled paths
            zip_ref.extractall(UPLOAD_FOLDER)
        
        return {
            'status': 'success',
            'message': 'ZIP extracted',
            'files': zip_ref.namelist()
        }
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/upload/image', methods=['POST'])
def image_upload():
    """
    VULNERABLE: Image upload without proper validation
    Can upload malicious files disguised as images
    """
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    
    # VULNERABLE: Only checking MIME type from request (client-controlled)
    mime_type = request.files['file'].content_type
    
    if not mime_type.startswith('image/'):
        return {'error': 'Only images allowed'}, 400
    
    # VULNERABLE: Not validating actual file content
    # A PHP script can be uploaded with image MIME type
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    return {
        'status': 'success',
        'filename': filename,
        'mime_type': mime_type,
        'url': f'/serve/{filename}'
    }

# Example Exploits:
"""
1. Path Traversal Upload:
   POST /upload/custom_name
   custom_name=../../etc/cron.d/malicious

2. Double Extension Bypass:
   Upload: shell.php.jpg
   If server processes .php, code execution achieved

3. Null Byte Injection:
   Filename: shell.php%00.jpg
   Server might truncate at null byte

4. Zip Slip:
   Create ZIP with entries like: ../../etc/passwd

5. Path Traversal Download:
   GET /download/../../etc/passwd

6. Arbitrary File Deletion:
   GET /delete/../../important_file

7. Executable Upload:
   Upload .py, .exe, .sh files via /upload/no_check

8. Overwrite Critical Files:
   Upload with filename: ../app.py
"""

if __name__ == '__main__':
    app.run(debug=True, port=5004)
