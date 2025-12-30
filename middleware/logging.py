"""
Request Logging Middleware
Logs all incoming requests and responses
"""

import logging
import time
from flask import request, g
from functools import wraps

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def request_logger(app):
    """
    Register request logging middleware with Flask app
    
    Usage:
        request_logger(app)
    """
    
    @app.before_request
    def before_request():
        """Log request details and start timer"""
        g.start_time = time.time()
        
        logger.info(
            f"Request: {request.method} {request.path} "
            f"from {request.remote_addr}"
        )
        
        # Log request body for POST/PUT (exclude sensitive data)
        if request.method in ['POST', 'PUT', 'PATCH']:
            if request.is_json:
                data = request.get_json()
                # Remove sensitive fields
                safe_data = {k: v for k, v in data.items() 
                           if k not in ['password', 'token', 'api_key']}
                logger.info(f"Request Body: {safe_data}")
    
    @app.after_request
    def after_request(response):
        """Log response details and duration"""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            
            logger.info(
                f"Response: {response.status_code} "
                f"for {request.method} {request.path} "
                f"in {duration:.3f}s"
            )
        
        return response
    
    @app.teardown_request
    def teardown_request(exception=None):
        """Log any errors during request"""
        if exception:
            logger.error(
                f"Error during request {request.method} {request.path}: "
                f"{str(exception)}"
            )


def log_function_call(f):
    """
    Decorator to log function calls
    
    Usage:
        @log_function_call
        def some_function():
            pass
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        logger.info(f"Calling function: {f.__name__}")
        start_time = time.time()
        
        try:
            result = f(*args, **kwargs)
            duration = time.time() - start_time
            logger.info(f"Function {f.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            logger.error(f"Error in function {f.__name__}: {str(e)}")
            raise
    
    return decorated
