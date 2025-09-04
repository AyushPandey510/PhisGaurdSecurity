import time
import hashlib
from typing import Any, Optional
import os

class SimpleCache:
    """Simple in-memory cache with TTL support"""

    def __init__(self, default_ttl: int = 300):  # 5 minutes default
        self.cache = {}
        self.default_ttl = default_ttl

    def _make_key(self, key: str) -> str:
        """Create a consistent cache key"""
        return hashlib.md5(key.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        cache_key = self._make_key(key)
        if cache_key in self.cache:
            value, expiry = self.cache[cache_key]
            if time.time() < expiry:
                return value
            else:
                # Remove expired entry
                del self.cache[cache_key]
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL"""
        cache_key = self._make_key(key)
        expiry = time.time() + (ttl or self.default_ttl)
        self.cache[cache_key] = (value, expiry)

    def delete(self, key: str) -> None:
        """Delete value from cache"""
        cache_key = self._make_key(key)
        if cache_key in self.cache:
            del self.cache[cache_key]

    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()

    def cleanup(self) -> int:
        """Remove expired entries and return count of removed items"""
        current_time = time.time()
        expired_keys = [
            key for key, (_, expiry) in self.cache.items()
            if current_time >= expiry
        ]
        for key in expired_keys:
            del self.cache[key]
        return len(expired_keys)

# Global cache instance
cache = SimpleCache()

def get_cache():
    """Get the global cache instance"""
    return cache

def cached(ttl: Optional[int] = None):
    """Decorator to cache function results"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            key_parts = [func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
            cache_key = "|".join(key_parts)

            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        return wrapper
    return decorator