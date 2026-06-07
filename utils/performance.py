"""
Performance monitoring and latency tracking.
Tracks request latencies and calculates performance improvements.
"""
from functools import wraps
import time
import logging
from collections import deque
import threading

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """Thread-safe performance monitor for tracking latencies."""
    
    def __init__(self, max_samples=1000):
        self._lock = threading.RLock()
        self.latencies = deque(maxlen=max_samples)
        self.baseline_latencies = deque(maxlen=100)  # Baseline before optimizations
        self.baseline_set = False
    
    def record_latency(self, latency_ms, is_baseline=False):
        """Record a latency measurement."""
        with self._lock:
            if is_baseline:
                self.baseline_latencies.append(latency_ms)
            else:
                self.latencies.append(latency_ms)
    
    def set_baseline(self):
        """Set current measurements as baseline."""
        with self._lock:
            if self.latencies:
                self.baseline_latencies.extend(self.latencies)
                self.baseline_set = True
                logger.info("Baseline performance metrics set")
    
    def get_average_latency(self):
        """Get average latency in milliseconds."""
        with self._lock:
            if not self.latencies:
                return 0
            return sum(self.latencies) / len(self.latencies)
    
    def get_baseline_average_latency(self):
        """Get baseline average latency in milliseconds."""
        with self._lock:
            if not self.baseline_latencies:
                return 0
            return sum(self.baseline_latencies) / len(self.baseline_latencies)
    
    def calculate_improvement(self):
        """Calculate latency improvement percentage."""
        with self._lock:
            baseline = self.get_baseline_average_latency()
            current = self.get_average_latency()

            if baseline == 0:
                return 0

            improvement = ((baseline - current) / baseline) * 100
            return max(0, improvement)
    
    def get_stats(self):
        """Get performance statistics."""
        with self._lock:
            improvement = self.calculate_improvement()
            return {
                'current_avg_latency_ms': round(self.get_average_latency(), 2),
                'baseline_avg_latency_ms': round(self.get_baseline_average_latency(), 2),
                'latency_reduction_percent': round(improvement, 2),
                'samples': len(self.latencies),
                'baseline_samples': len(self.baseline_latencies),
                'baseline_set': self.baseline_set
            }

# Global performance monitor
performance_monitor = PerformanceMonitor()


def measure_latency(func):
    """Decorator to measure function execution latency."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            latency_ms = (time.time() - start_time) * 1000
            performance_monitor.record_latency(latency_ms)
            return result
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            performance_monitor.record_latency(latency_ms)
            raise
    return wrapper
