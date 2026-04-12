"""
Caching system for stock prices and API responses.
Uses in-memory cache with TTL (Time To Live) support.
Can be upgraded to Redis for distributed caching.
"""
from datetime import datetime, timedelta
from collections import OrderedDict
import threading
import logging

logger = logging.getLogger(__name__)

class TTLCache:
    """Thread-safe TTL cache with LRU eviction."""
    
    def __init__(self, max_size=1000, default_ttl=60):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum number of items in cache
            default_ttl: Default time-to-live in seconds
        """
        self._lock = threading.Lock()
        self._cache = OrderedDict()  # OrderedDict for LRU
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
    
    def get(self, key):
        """Get value from cache if not expired."""
        with self._lock:
            if key not in self._cache:
                self.misses += 1
                return None
            
            value, expiry = self._cache[key]
            
            # Check if expired
            if datetime.now() > expiry:
                del self._cache[key]
                self.misses += 1
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(key)
            self.hits += 1
            return value
    
    def set(self, key, value, ttl=None):
        """Set value in cache with TTL."""
        with self._lock:
            if ttl is None:
                ttl = self.default_ttl
            
            expiry = datetime.now() + timedelta(seconds=ttl)
            
            # Remove if exists
            if key in self._cache:
                del self._cache[key]
            
            # Add new entry
            self._cache[key] = (value, expiry)
            
            # Evict if over size limit
            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)  # Remove oldest
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0
    
    def get_stats(self):
        """Get cache statistics."""
        with self._lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate_percent': round(hit_rate, 2)
            }

# Global cache instances
price_cache = TTLCache(max_size=2000, default_ttl=10)  # 10 second TTL for prices
api_cache = TTLCache(max_size=500, default_ttl=30)  # 30 second TTL for API responses
