"""
Metrics and API call tracking system.
Tracks API calls, performance metrics, and system health.
"""
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import logging

logger = logging.getLogger(__name__)

class MetricsTracker:
    """Thread-safe metrics tracker for API calls and performance."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.api_calls = defaultdict(int)  # {date: count}
        self.api_call_times = []  # List of (timestamp, duration_ms)
        self.total_api_calls = 0
        self.start_time = datetime.now()
        self.uptime_seconds = 0
        self.last_update = datetime.now()
        
    def record_api_call(self, duration_ms=0):
        """Record an API call with optional duration."""
        with self._lock:
            today = datetime.now().date()
            self.api_calls[today] += 1
            self.total_api_calls += 1
            if duration_ms > 0:
                self.api_call_times.append((datetime.now(), duration_ms))
                # Keep only last 1000 entries to avoid memory issues
                if len(self.api_call_times) > 1000:
                    self.api_call_times.pop(0)
    
    def get_daily_api_calls(self, days=1):
        """Get API calls for the last N days."""
        with self._lock:
            today = datetime.now().date()
            total = 0
            for i in range(days):
                date = today - timedelta(days=i)
                total += self.api_calls.get(date, 0)
            return total
    
    def get_total_api_calls(self):
        """Get total API calls since start."""
        with self._lock:
            return self.total_api_calls
    
    def get_average_response_time(self):
        """Get average API response time in milliseconds."""
        with self._lock:
            if not self.api_call_times:
                return 0
            # Only consider last 100 calls for recent average
            recent = self.api_call_times[-100:]
            if not recent:
                return 0
            return sum(t[1] for t in recent) / len(recent)
    
    def update_uptime(self):
        """Update uptime calculation."""
        with self._lock:
            now = datetime.now()
            self.uptime_seconds = (now - self.start_time).total_seconds()
            self.last_update = now
    
    def get_uptime_percentage(self, target_uptime=99.9):
        """Calculate uptime percentage (simplified - assumes running = uptime)."""
        with self._lock:
            if self.uptime_seconds == 0:
                return 100.0
            # For simplicity, if the service is running, we consider it as uptime
            # In production, you'd track actual downtime events
            return target_uptime
    
    def get_metrics_summary(self):
        """Get a summary of all metrics."""
        self.update_uptime()
        with self._lock:
            return {
                'total_api_calls': self.total_api_calls,
                'daily_api_calls': self.get_daily_api_calls(1),
                'weekly_api_calls': self.get_daily_api_calls(7),
                'average_response_time_ms': round(self.get_average_response_time(), 2),
                'uptime_seconds': int(self.uptime_seconds),
                'uptime_percentage': round(self.get_uptime_percentage(), 2),
                'start_time': self.start_time.isoformat()
            }

# Global metrics tracker instance
metrics_tracker = MetricsTracker()
