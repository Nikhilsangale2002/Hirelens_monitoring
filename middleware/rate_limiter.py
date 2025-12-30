"""
Rate Limiting Middleware
Prevents API abuse by limiting request frequency
"""

from functools import wraps
from flask import request, jsonify
import time
from collections import defaultdict
import threading

# In-memory storage for rate limiting (use Redis in production)
rate_limit_storage = defaultdict(list)
storage_lock = threading.Lock()


class RateLimiter:
    """Rate limiter with sliding window algorithm"""
    
    @staticmethod
    def is_rate_limited(key, limit, window):
        """
        Check if request should be rate limited
        
        Args:
            key: Identifier (IP address or user ID)
            limit: Maximum requests allowed
            window: Time window in seconds
            
        Returns:
            bool: True if rate limited, False otherwise
        """
        current_time = time.time()
        
        with storage_lock:
            # Get request timestamps for this key
            timestamps = rate_limit_storage[key]
            
            # Remove timestamps outside the window
            timestamps[:] = [ts for ts in timestamps if current_time - ts < window]
            
            # Check if limit exceeded
            if len(timestamps) >= limit:
                return True
            
            # Add current timestamp
            timestamps.append(current_time)
            rate_limit_storage[key] = timestamps
            
            return False
    
    @staticmethod
    def cleanup_old_entries(max_age=3600):
        """Remove entries older than max_age seconds"""
        current_time = time.time()
        
        with storage_lock:
            keys_to_delete = []
            
            for key, timestamps in rate_limit_storage.items():
                # Remove old timestamps
                timestamps[:] = [ts for ts in timestamps if current_time - ts < max_age]
                
                # Mark empty keys for deletion
                if not timestamps:
                    keys_to_delete.append(key)
            
            # Delete empty keys
            for key in keys_to_delete:
                del rate_limit_storage[key]


def rate_limit(limit=100, window=60, key_func=None):
    """
    Decorator for rate limiting
    
    Args:
        limit: Maximum requests allowed (default: 100)
        window: Time window in seconds (default: 60)
        key_func: Function to generate rate limit key (default: uses IP address)
    
    Usage:
        @rate_limit(limit=10, window=60)
        def some_route():
            pass
        
        # Custom key (e.g., user ID)
        @rate_limit(limit=100, window=3600, key_func=lambda: get_jwt_identity())
        def user_route():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Determine rate limit key
            if key_func:
                try:
                    key = key_func()
                except Exception:
                    key = request.remote_addr
            else:
                key = request.remote_addr
            
            # Check rate limit
            if RateLimiter.is_rate_limited(key, limit, window):
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Maximum {limit} requests per {window} seconds',
                    'retry_after': window
                }), 429
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


def global_rate_limiter(app, limit=1000, window=60):
    """
    Apply rate limiting to all requests globally
    
    Usage:
        global_rate_limiter(app, limit=1000, window=60)
    """
    
    @app.before_request
    def check_rate_limit():
        # Skip rate limiting for health check
        if request.path == '/api/health':
            return None
        
        key = request.remote_addr
        
        if RateLimiter.is_rate_limited(key, limit, window):
            return jsonify({
                'error': 'Too many requests',
                'message': f'Global rate limit: {limit} requests per {window} seconds',
                'retry_after': window
            }), 429


# Plan-based rate limits
PLAN_RATE_LIMITS = {
    'Starter': {'limit': 100, 'window': 3600},    # 100 requests/hour
    'Pro': {'limit': 500, 'window': 3600},        # 500 requests/hour
    'Enterprise': {'limit': 5000, 'window': 3600} # 5000 requests/hour
}


def plan_based_rate_limit(f):
    """
    Rate limit based on user's subscription plan
    Requires authentication
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            from models.user import User
            
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            current_user = User.query.get(user_id)
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
            
            # Get plan-specific rate limit
            plan_limits = PLAN_RATE_LIMITS.get(current_user.plan, PLAN_RATE_LIMITS['Starter'])
            limit = plan_limits['limit']
            window = plan_limits['window']
            
            # Check rate limit
            key = f"user_{user_id}"
            if RateLimiter.is_rate_limited(key, limit, window):
                return jsonify({
                    'error': 'Rate limit exceeded for your plan',
                    'plan': current_user.plan,
                    'limit': limit,
                    'window': window,
                    'message': 'Consider upgrading your plan for higher limits'
                }), 429
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Rate limit check failed'}), 500
    
    return decorated
