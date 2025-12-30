"""
Authentication Middleware
JWT token verification and authorization decorators
"""

from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from models.user import User

def token_required(f):
    """
    Decorator to require valid JWT token
    Adds current_user to kwargs
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            current_user = User.query.get(user_id)
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
            
            return f(*args, current_user=current_user, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token'}), 401
    
    return decorated


def admin_required(f):
    """
    Decorator to require admin role
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            claims = get_jwt()
            
            if claims.get('role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            user_id = get_jwt_identity()
            current_user = User.query.get(user_id)
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
            
            return f(*args, current_user=current_user, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Unauthorized access'}), 401
    
    return decorated


def plan_required(required_plans):
    """
    Decorator to require specific subscription plan
    
    Usage:
        @plan_required(['Pro', 'Enterprise'])
        def some_route():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                current_user = User.query.get(user_id)
                
                if not current_user:
                    return jsonify({'error': 'User not found'}), 404
                
                if current_user.plan not in required_plans:
                    return jsonify({
                        'error': f'This feature requires {" or ".join(required_plans)} plan',
                        'current_plan': current_user.plan,
                        'required_plans': required_plans
                    }), 403
                
                return f(*args, current_user=current_user, **kwargs)
            except Exception as e:
                return jsonify({'error': 'Unauthorized access'}), 401
        
        return decorated
    return decorator


def optional_token(f):
    """
    Decorator that allows both authenticated and unauthenticated access
    Adds current_user=None if not authenticated
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            
            if user_id:
                current_user = User.query.get(user_id)
            else:
                current_user = None
            
            return f(*args, current_user=current_user, **kwargs)
        except Exception:
            return f(*args, current_user=None, **kwargs)
    
    return decorated
