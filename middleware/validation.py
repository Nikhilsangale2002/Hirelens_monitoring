"""
Request Validation Middleware
Validates request data against defined schemas
"""

from functools import wraps
from flask import request, jsonify
import re


def validate_json(required_fields=None, optional_fields=None, validators=None):
    """
    Decorator to validate JSON request body
    
    Args:
        required_fields: List of required field names
        optional_fields: List of optional field names
        validators: Dict of field_name: validator_function pairs
    
    Usage:
        @validate_json(
            required_fields=['email', 'password'],
            validators={'email': is_valid_email}
        )
        def signup():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'Request body is empty'}), 400
            
            # Check required fields
            if required_fields:
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    return jsonify({
                        'error': 'Missing required fields',
                        'missing_fields': missing_fields
                    }), 400
            
            # Check for unknown fields
            if required_fields or optional_fields:
                allowed_fields = set(required_fields or []) | set(optional_fields or [])
                unknown_fields = [field for field in data.keys() if field not in allowed_fields]
                if unknown_fields:
                    return jsonify({
                        'error': 'Unknown fields in request',
                        'unknown_fields': unknown_fields
                    }), 400
            
            # Run custom validators
            if validators:
                for field, validator_func in validators.items():
                    if field in data:
                        is_valid, error_message = validator_func(data[field])
                        if not is_valid:
                            return jsonify({
                                'error': f'Validation failed for field: {field}',
                                'message': error_message
                            }), 400
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


def validate_file_upload(allowed_extensions=None, max_size=None):
    """
    Decorator to validate file uploads
    
    Args:
        allowed_extensions: List of allowed file extensions (e.g., ['pdf', 'docx'])
        max_size: Maximum file size in bytes
    
    Usage:
        @validate_file_upload(allowed_extensions=['pdf', 'docx'], max_size=5*1024*1024)
        def upload_resume():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Check file extension
            if allowed_extensions:
                ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                if ext not in allowed_extensions:
                    return jsonify({
                        'error': 'Invalid file type',
                        'allowed_types': allowed_extensions
                    }), 400
            
            # Check file size
            if max_size:
                file.seek(0, 2)  # Seek to end
                size = file.tell()
                file.seek(0)  # Reset to beginning
                
                if size > max_size:
                    return jsonify({
                        'error': 'File too large',
                        'max_size': f'{max_size // (1024*1024)}MB'
                    }), 413
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


# Common validators
def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True, None
    return False, 'Invalid email format'


def is_valid_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, 'Password must contain at least one special character'
    return True, None


def is_valid_phone(phone):
    """Validate phone number format"""
    pattern = r'^\+?1?\d{9,15}$'
    if re.match(pattern, phone):
        return True, None
    return False, 'Invalid phone number format'


def is_valid_url(url):
    """Validate URL format"""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    if re.match(pattern, url):
        return True, None
    return False, 'Invalid URL format'


def is_not_empty(value):
    """Check if value is not empty"""
    if value and str(value).strip():
        return True, None
    return False, 'Value cannot be empty'


def min_length(length):
    """Return validator for minimum string length"""
    def validator(value):
        if len(str(value)) >= length:
            return True, None
        return False, f'Minimum length is {length}'
    return validator


def max_length(length):
    """Return validator for maximum string length"""
    def validator(value):
        if len(str(value)) <= length:
            return True, None
        return False, f'Maximum length is {length}'
    return validator


def in_range(min_val, max_val):
    """Return validator for numeric range"""
    def validator(value):
        try:
            num = float(value)
            if min_val <= num <= max_val:
                return True, None
            return False, f'Value must be between {min_val} and {max_val}'
        except (ValueError, TypeError):
            return False, 'Value must be a number'
    return validator


def is_in_list(allowed_values):
    """Return validator for allowed values"""
    def validator(value):
        if value in allowed_values:
            return True, None
        return False, f'Value must be one of: {", ".join(map(str, allowed_values))}'
    return validator
