"""
CORS Middleware Configuration
Cross-Origin Resource Sharing settings
"""

from flask_cors import CORS


def configure_cors(app):
    """
    Configure CORS for the Flask application
    
    Args:
        app: Flask application instance
    """
    
    # Development configuration - Allow all origins
    if app.config.get('FLASK_ENV') == 'development':
        CORS(app, 
             origins='*',
             allow_headers=['Content-Type', 'Authorization'],
             methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
             supports_credentials=True)
    
    # Production configuration - Specific origins only
    else:
        allowed_origins = app.config.get('ALLOWED_ORIGINS', [
            'https://yourdomain.com',
            'https://www.yourdomain.com',
            'https://app.yourdomain.com'
        ])
        
        CORS(app,
             origins=allowed_origins,
             allow_headers=['Content-Type', 'Authorization'],
             methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
             supports_credentials=True,
             max_age=3600)  # Cache preflight requests for 1 hour


def add_cors_headers(app):
    """
    Manually add CORS headers to responses
    Alternative to Flask-CORS
    """
    
    @app.after_request
    def after_request(response):
        # Get allowed origins
        allowed_origins = app.config.get('ALLOWED_ORIGINS', ['*'])
        origin = request.headers.get('Origin')
        
        # Set CORS headers
        if origin in allowed_origins or '*' in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin or '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Max-Age'] = '3600'
        
        return response
