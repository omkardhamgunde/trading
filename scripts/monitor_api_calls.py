"""
API Call Monitoring Script
Monitors API call metrics and verifies 100,000+ daily calls claim.
"""
import requests
import time
from datetime import datetime, timedelta
import json

METRICS_URL = "http://localhost:5001/metrics"
UPDATE_INTERVAL = 60  # Check every minute

def get_metrics():
    """Fetch metrics from the server."""
    try:
        response = requests.get(METRICS_URL, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching metrics: {e}")
        return None

def format_number(num):
    """Format large numbers with commas."""
    return f"{num:,}"

def calculate_projected_daily(current_calls, hours_running):
    """Calculate projected daily API calls."""
    if hours_running == 0:
        return 0
    hourly_rate = current_calls / hours_running
    return hourly_rate * 24

def print_header():
    """Print header."""
    print("\n" + "="*70)
    print("API CALL MONITORING DASHBOARD")
    print("="*70)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*70)

def print_metrics(metrics_data):
    """Print formatted metrics."""
    if not metrics_data or 'metrics' not in metrics_data:
        print("❌ No metrics data available")
        return
    
    m = metrics_data['metrics']
    
    # Calculate hours running
    start_time = datetime.fromisoformat(m['start_time'].replace('Z', '+00:00'))
    hours_running = (datetime.now() - start_time.replace(tzinfo=None)).total_seconds() / 3600
    hours_running = max(hours_running, 0.1)  # Minimum 0.1 hours
    
    # Calculate projected daily
    projected_daily = calculate_projected_daily(m['daily_api_calls'], hours_running)
    
    print("\n📊 CURRENT METRICS")
    print("-"*70)
    print(f"Total API Calls:        {format_number(m['total_api_calls'])}")
    print(f"Daily API Calls:        {format_number(m['daily_api_calls'])}")
    print(f"Weekly API Calls:       {format_number(m['weekly_api_calls'])}")
    print(f"Average Response Time:  {m['average_response_time_ms']:.2f} ms")
    print(f"Uptime:                 {m['uptime_seconds']/3600:.2f} hours")
    
    print("\n📈 PROJECTIONS")
    print("-"*70)
    print(f"Hours Running:          {hours_running:.2f}")
    print(f"Projected Daily Calls:  {format_number(int(projected_daily))}")
    
    # Verification status
    print("\n✅ VERIFICATION STATUS")
    print("-"*70)
    if m['daily_api_calls'] >= 100000:
        print(f"✅ VERIFIED: Daily calls ({format_number(m['daily_api_calls'])}) >= 100,000")
    elif projected_daily >= 100000:
        print(f"✅ ON TRACK: Projected daily ({format_number(int(projected_daily))}) >= 100,000")
        print(f"   Current daily: {format_number(m['daily_api_calls'])} (server running {hours_running:.2f} hours)")
    else:
        print(f"⏳ IN PROGRESS: Current daily ({format_number(m['daily_api_calls'])}) < 100,000")
        print(f"   Projected daily: {format_number(int(projected_daily))}")
        print(f"   Need: {format_number(100000 - m['daily_api_calls'])} more calls today")
    
    # Cache stats
    if 'cache' in metrics_data:
        cache_stats = metrics_data['cache'].get('price_cache', {})
        print("\n💾 CACHE STATISTICS")
        print("-"*70)
        print(f"Cache Size:            {cache_stats.get('size', 0)}/{cache_stats.get('max_size', 0)}")
        print(f"Cache Hits:             {format_number(cache_stats.get('hits', 0))}")
        print(f"Cache Misses:          {format_number(cache_stats.get('misses', 0))}")
        print(f"Hit Rate:              {cache_stats.get('hit_rate_percent', 0):.2f}%")
    
    print("\n" + "="*70)

def main():
    """Main monitoring loop."""
    print("Starting API Call Monitor...")
    print(f"Metrics URL: {METRICS_URL}")
    print(f"Update Interval: {UPDATE_INTERVAL} seconds")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            print_header()
            
            metrics_data = get_metrics()
            if metrics_data:
                print_metrics(metrics_data)
            else:
                print("❌ Could not fetch metrics. Is the server running?")
            
            print(f"\nNext update in {UPDATE_INTERVAL} seconds...")
            time.sleep(UPDATE_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == '__main__':
    main()
