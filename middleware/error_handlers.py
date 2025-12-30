"""
Error Handling Middleware
Centralized error handling for the application
"""

from flask import jsonify
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)


def register_error_handlers(app):
    """
    Register error handlers with Flask app
    
    Usage:
        register_error_handlers(app)
    """
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request"""
        logger.warning(f"Bad Request: {str(error)}")
        return jsonify({
            'error': 'Bad Request',
            'message': str(error) if str(error) else 'Invalid request data'
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle 401 Unauthorized"""
        logger.warning(f"Unauthorized: {str(error)}")
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required'
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 Forbidden"""
        logger.warning(f"Forbidden: {str(error)}")
        return jsonify({
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource'
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found"""
        logger.info(f"Not Found: {str(error)}")
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found'
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle 405 Method Not Allowed"""
        logger.warning(f"Method Not Allowed: {str(error)}")
        return jsonify({
            'error': 'Method Not Allowed',
            'message': 'The HTTP method is not allowed for this endpoint'
        }), 405
    
    @app.errorhandler(409)
    def conflict(error):
        """Handle 409 Conflict"""
        logger.warning(f"Conflict: {str(error)}")
        return jsonify({
            'error': 'Conflict',
            'message': str(error) if str(error) else 'Resource conflict'
        }), 409
    
    @app.errorhandler(413)
    def request_entity_too_large(error):
        """Handle 413 Payload Too Large"""
        logger.warning(f"Payload Too Large: {str(error)}")
        return jsonify({
            'error': 'Payload Too Large',
            'message': 'File size exceeds maximum allowed size'
        }), 413
    
    @app.errorhandler(422)
    def unprocessable_entity(error):
        """Handle 422 Unprocessable Entity"""
        logger.warning(f"Unprocessable Entity: {str(error)}")
        return jsonify({
            'error': 'Unprocessable Entity',
            'message': 'Request data validation failed'
        }), 422
    
    @app.errorhandler(429)
    def too_many_requests(error):
        """Handle 429 Too Many Requests"""
        logger.warning(f"Rate Limit Exceeded: {str(error)}")
        return jsonify({
            'error': 'Too Many Requests',
            'message': 'Rate limit exceeded. Please try again later.'
        }), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 Internal Server Error"""
        logger.error(f"Internal Server Error: {str(error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred. Please try again later.'
        }), 500
    
    @app.errorhandler(503)
    def service_unavailable(error):
        """Handle 503 Service Unavailable"""
        logger.error(f"Service Unavailable: {str(error)}")
        return jsonify({
            'error': 'Service Unavailable',
            'message': 'The service is temporarily unavailable'
        }), 503
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        """Handle all HTTP exceptions"""
        logger.warning(f"HTTP Exception {error.code}: {str(error)}")
        return jsonify({
            'error': error.name,
            'message': error.description
        }), error.code
    
    @app.errorhandler(SQLAlchemyError)
    def handle_database_error(error):
        """Handle database errors"""
        logger.error(f"Database Error: {str(error)}")
        return jsonify({
            'error': 'Database Error',
            'message': 'A database error occurred. Please try again later.'
        }), 500
    
    @app.errorhandler(ValueError)
    def handle_value_error(error):
        """Handle value errors"""
        logger.warning(f"Value Error: {str(error)}")
        return jsonify({
            'error': 'Invalid Value',
            'message': str(error)
        }), 400
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle all other unexpected errors"""
        logger.error(f"Unexpected Error: {str(error)}", exc_info=True)
        return jsonify({
            'error': 'Unexpected Error',
            'message': 'An unexpected error occurred. Please try again later.'
        }), 500


class APIException(Exception):
    """Custom exception for API errors"""
    
    def __init__(self, message, status_code=400, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload
    
    def to_dict(self):
        """Convert exception to dictionary"""
        rv = dict(self.payload or ())
        rv['error'] = self.__class__.__name__
        rv['message'] = self.message
        return rv


def register_custom_exception(app):
    """Register custom exception handler"""
    
    @app.errorhandler(APIException)
    def handle_api_exception(error):
        """Handle custom API exceptions"""
        logger.warning(f"API Exception: {error.message}")
        return jsonify(error.to_dict()), error.status_code
