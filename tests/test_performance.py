from utils.performance import PerformanceMonitor


def test_performance_monitor_reports_latency_reduction_without_deadlock():
    monitor = PerformanceMonitor()
    monitor.record_latency(100, is_baseline=True)
    monitor.record_latency(40)

    stats = monitor.get_stats()

    assert stats["baseline_avg_latency_ms"] == 100
    assert stats["current_avg_latency_ms"] == 40
    assert stats["latency_reduction_percent"] == 60
