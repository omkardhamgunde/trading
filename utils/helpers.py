"""
Helper utility functions.
"""
import pytz
from datetime import datetime


def crossover(series1, series2):
    """Check if series1 crosses over series2."""
    return series1[-2] < series2[-2] and series1[-1] > series2[-1]


def validate_dates(data):
    """Ensure data doesn't contain future dates."""
    now = datetime.now(pytz.utc).date()
    latest_date = data.index[-1].date()
    
    if latest_date > now:
        print(f"⚠️ Data anomaly: Future date {latest_date} detected")
        return False
        
    if data.index[0].date() > now:
        print(f"⚠️ Data anomaly: Start date {data.index[0].date()} is in future")
        return False
        
    return True
