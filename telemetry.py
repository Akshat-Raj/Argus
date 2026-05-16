import time
import psutil
import threading
import contextlib
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class TelemetryData:
    start_time: float
    end_time: float
    duration_sec: float
    peak_cpu_percent: float
    avg_cpu_percent: float
    peak_memory_mb: float
    avg_memory_mb: float

class ResourceMonitor(threading.Thread):
    def __init__(self, interval: float = 0.1):
        super().__init__()
        self.interval = interval
        self.running = False
        self.cpu_samples: List[float] = []
        self.memory_samples: List[float] = []

    def run(self):
        self.running = True
        process = psutil.Process()
        # Call cpu_percent once to initialize the baseline
        process.cpu_percent(interval=None)
        time.sleep(self.interval)
        
        while self.running:
            try:
                self.cpu_samples.append(process.cpu_percent(interval=None))
                self.memory_samples.append(process.memory_info().rss / (1024 * 1024))
            except psutil.NoSuchProcess:
                pass
            time.sleep(self.interval)

    def stop(self):
        self.running = False

@contextlib.contextmanager
def track_telemetry():
    """
    Context manager to track telemetry.
    Usage:
        with track_telemetry() as telemetry_results:
            # do work
        
        # telemetry_results[0] will contain the TelemetryData
    """
    monitor = ResourceMonitor()
    start_time = time.time()
    monitor.start()
    
    result_container: List[TelemetryData] = []
    
    try:
        yield result_container
    finally:
        monitor.stop()
        monitor.join()
        end_time = time.time()
        
        avg_cpu = sum(monitor.cpu_samples) / len(monitor.cpu_samples) if monitor.cpu_samples else 0.0
        peak_cpu = max(monitor.cpu_samples) if monitor.cpu_samples else 0.0
        avg_mem = sum(monitor.memory_samples) / len(monitor.memory_samples) if monitor.memory_samples else 0.0
        peak_mem = max(monitor.memory_samples) if monitor.memory_samples else 0.0
        
        data = TelemetryData(
            start_time=start_time,
            end_time=end_time,
            duration_sec=end_time - start_time,
            peak_cpu_percent=peak_cpu,
            avg_cpu_percent=avg_cpu,
            peak_memory_mb=peak_mem,
            avg_memory_mb=avg_mem
        )
        result_container.append(data)
