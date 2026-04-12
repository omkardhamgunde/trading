"""
Health check and metrics endpoints.
"""
from flask import Blueprint, jsonify
from utils.metrics import metrics_tracker
from utils.cache import price_cache, api_cache
from utils.performance import performance_monitor
import logging

logger = logging.getLogger(__name__)

def init_health_routes():
    """Initialize health check routes."""
    health_bp = Blueprint('health', __name__)
    
    @health_bp.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        try:
            metrics_tracker.update_uptime()
            return jsonify({
                'status': 'healthy',
                'uptime_seconds': int(metrics_tracker.uptime_seconds),
                'uptime_percentage': round(metrics_tracker.get_uptime_percentage(), 2)
            }), 200
        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return jsonify({'status': 'unhealthy', 'error': str(e)}), 500
    
    @health_bp.route('/metrics', methods=['GET'])
    def get_metrics():
        """Get application metrics."""
        try:
            metrics = metrics_tracker.get_metrics_summary()
            cache_stats = {
                'price_cache': price_cache.get_stats(),
                'api_cache': api_cache.get_stats()
            }
            performance_stats = performance_monitor.get_stats()
            
            # Calculate projected daily API calls
            from datetime import datetime
            start_time = datetime.fromisoformat(metrics['start_time'].replace('Z', '+00:00'))
            hours_running = max((datetime.now() - start_time.replace(tzinfo=None)).total_seconds() / 3600, 0.1)
            
            if hours_running > 0:
                hourly_rate = metrics['daily_api_calls'] / hours_running
                projected_daily = hourly_rate * 24
            else:
                projected_daily = 0
            
            # Add verification status
            verification = {
                'target_daily_calls': 100000,
                'current_daily_calls': metrics['daily_api_calls'],
                'projected_daily_calls': int(projected_daily),
                'verified': metrics['daily_api_calls'] >= 100000 or projected_daily >= 100000,
                'hours_running': round(hours_running, 2)
            }
            
            return jsonify({
                'metrics': metrics,
                'cache': cache_stats,
                'performance': performance_stats,
                'verification': verification
            }), 200
        except Exception as e:
            logger.error(f"Error getting metrics: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @health_bp.route('/performance/baseline', methods=['POST'])
    def set_baseline():
        """Set current performance as baseline for comparison."""
        try:
            performance_monitor.set_baseline()
            return jsonify({'message': 'Baseline set successfully'}), 200
        except Exception as e:
            logger.error(f"Error setting baseline: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @health_bp.route('/cache/clear', methods=['POST'])
    def clear_cache():
        """Clear all caches (useful for debugging)."""
        try:
            price_cache.clear()
            api_cache.clear()
            return jsonify({'message': 'Cache cleared successfully'}), 200
        except Exception as e:
            logger.error(f"Error clearing cache: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    return health_bp
