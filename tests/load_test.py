"""
Load testing script to verify 50+ simultaneous users capability.
Uses concurrent WebSocket connections to simulate multiple users.
"""
import socketio
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import requests
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test stock symbols to use
TEST_STOCKS = ['AAPL', 'GOOGL', 'MSFT', 'TSLA', 'AMZN', 'META', 'NVDA', 'NFLX']

class LoadTestClient:
    """Simulates a single user connection."""
    
    def __init__(self, user_id, server_url='http://127.0.0.1:5001', create_test_data=True):
        self.user_id = user_id
        self.server_url = server_url
        self.sio = socketio.Client()
        self.connected = False
        self.messages_received = 0
        self.price_updates = 0
        self.holdings_updates = 0
        self.create_test_data = create_test_data
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup WebSocket event handlers."""
        @self.sio.on('connect')
        def on_connect():
            self.connected = True
            logger.debug(f"Client {self.user_id} connected")
            # Subscribe to watchlist and holdings
            self.sio.emit('subscribe_watchlist', {'user_id': self.user_id})
            self.sio.emit('subscribe_holdings', {'user_id': self.user_id})
        
        @self.sio.on('disconnect')
        def on_disconnect():
            self.connected = False
            logger.debug(f"Client {self.user_id} disconnected")
        
        @self.sio.on('price_update')
        def on_price_update(data):
            self.messages_received += 1
            self.price_updates += 1
            logger.debug(f"Client {self.user_id} received price_update")
        
        @self.sio.on('holdings_update')
        def on_holdings_update(data):
            self.messages_received += 1
            self.holdings_updates += 1
            logger.debug(f"Client {self.user_id} received holdings_update")
    
    def create_watchlist_data(self, mysql_connection_string=None):
        """Create test watchlist data for this user (if database access available)."""
        # Note: This would require database access, which we don't have in the test
        # For now, we'll rely on the fact that indices are always sent
        pass
    
    def connect(self):
        """Connect to the server."""
        try:
            self.sio.connect(self.server_url)
            return True
        except Exception as e:
            logger.error(f"Client {self.user_id} connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the server."""
        if self.connected:
            self.sio.disconnect()
    
    def get_stats(self):
        """Get connection statistics."""
        return {
            'user_id': self.user_id,
            'connected': self.connected,
            'messages_received': self.messages_received
        }


def run_load_test(num_users=50, duration_seconds=60):
    """
    Run load test with specified number of users.
    
    Args:
        num_users: Number of concurrent users to simulate
        duration_seconds: How long to keep connections alive
    """
    logger.info(f"Starting load test with {num_users} users for {duration_seconds} seconds...")
    logger.info("Note: Test users won't receive updates unless they have watchlist/holdings in DB")
    logger.info("This test verifies connection capability, not message delivery\n")
    
    clients = []
    connection_start_time = time.time()
    
    # Create and connect all clients
    logger.info("Connecting clients...")
    with ThreadPoolExecutor(max_workers=num_users) as executor:
        futures = []
        for i in range(1, num_users + 1):
            client = LoadTestClient(i, create_test_data=False)
            clients.append(client)
            futures.append(executor.submit(client.connect))
        
        # Wait for all connections with timeout
        connected_count = 0
        for future in futures:
            try:
                if future.result(timeout=10):
                    connected_count += 1
            except Exception as e:
                logger.debug(f"Connection failed: {e}")
        
        connection_time = time.time() - connection_start_time
        logger.info(f"Connected {connected_count}/{num_users} clients in {connection_time:.2f} seconds")
    
    if connected_count == 0:
        logger.error("No clients connected. Aborting test.")
        return None
    
    # Monitor connections during test
    logger.info(f"Running test for {duration_seconds} seconds...")
    logger.info("Monitoring connections and message delivery...")
    
    # Check connection health periodically
    check_interval = 10  # Check every 10 seconds
    checks = duration_seconds // check_interval
    for check in range(checks):
        time.sleep(check_interval)
        active_connections = sum(1 for c in clients if c.connected)
        total_messages = sum(c.messages_received for c in clients)
        logger.info(f"  [{check+1}/{checks}] Active: {active_connections}/{num_users}, Messages: {total_messages}")
    
    # Final wait
    remaining_time = duration_seconds % check_interval
    if remaining_time > 0:
        time.sleep(remaining_time)
    
    # Collect statistics
    logger.info("Collecting final statistics...")
    active_connections = sum(1 for c in clients if c.connected)
    total_messages = sum(c.messages_received for c in clients)
    total_price_updates = sum(c.price_updates for c in clients)
    total_holdings_updates = sum(c.holdings_updates for c in clients)
    
    stats = {
        'total_clients': num_users,
        'connected_clients': active_connections,
        'connection_success_rate': (active_connections / num_users) * 100,
        'total_messages': total_messages,
        'price_updates': total_price_updates,
        'holdings_updates': total_holdings_updates,
        'avg_messages_per_client': total_messages / active_connections if active_connections > 0 else 0,
        'connection_time_seconds': connection_time,
        'test_duration_seconds': duration_seconds
    }
    
    # Disconnect all clients
    logger.info("Disconnecting clients...")
    disconnect_start = time.time()
    for client in clients:
        try:
            client.disconnect()
        except:
            pass
    disconnect_time = time.time() - disconnect_start
    
    # Print results
    logger.info("\n" + "="*70)
    logger.info("LOAD TEST RESULTS")
    logger.info("="*70)
    logger.info(f"Total Clients:              {stats['total_clients']}")
    logger.info(f"Connected Clients:          {stats['connected_clients']}")
    logger.info(f"Connection Success Rate:    {stats['connection_success_rate']:.1f}%")
    logger.info(f"Connection Time:            {stats['connection_time_seconds']:.2f} seconds")
    logger.info(f"Test Duration:              {stats['test_duration_seconds']} seconds")
    logger.info(f"Disconnect Time:            {disconnect_time:.2f} seconds")
    logger.info("-"*70)
    logger.info(f"Total Messages Received:    {stats['total_messages']}")
    logger.info(f"  - Price Updates:          {stats['price_updates']}")
    logger.info(f"  - Holdings Updates:       {stats['holdings_updates']}")
    logger.info(f"Avg Messages per Client:     {stats['avg_messages_per_client']:.2f}")
    logger.info("="*70)
    
    # Verification
    logger.info("\n✅ VERIFICATION:")
    if stats['connected_clients'] >= 50:
        logger.info(f"✅ CONNECTION TEST PASSED: {stats['connected_clients']} simultaneous connections established")
    else:
        logger.warning(f"⚠️  CONNECTION TEST: Only {stats['connected_clients']} connections (target: 50+)")
    
    if stats['total_messages'] > 0:
        logger.info(f"✅ MESSAGE DELIVERY: {stats['total_messages']} messages received")
        logger.info("   (Note: Messages only sent if users have watchlist/holdings in database)")
    else:
        logger.warning("⚠️  MESSAGE DELIVERY: No messages received")
        logger.warning("   This is expected if test users don't have watchlist/holdings in database")
        logger.warning("   The connection test still verifies 50+ simultaneous WebSocket connections")
    
    logger.info("\n" + "="*70)
    
    return stats


if __name__ == '__main__':
    import sys
    
    num_users = 50
    duration = 60
    
    if len(sys.argv) > 1:
        num_users = int(sys.argv[1])
    if len(sys.argv) > 2:
        duration = int(sys.argv[2])
    
    run_load_test(num_users, duration)
