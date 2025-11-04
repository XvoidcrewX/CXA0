import psutil
import time
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime

class SystemMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.stats = {
            'cpu_percent': 0,
            'memory_percent': 0,
            'memory_used_mb': 0,
            'disk_usage_percent': 0,
            'network_sent_mb': 0,
            'network_recv_mb': 0
        }
        self.callbacks = []
        
    def start_monitoring(self):
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        net_io_start = psutil.net_io_counters()
        
        while self.monitoring:
            try:
                self.stats['cpu_percent'] = psutil.cpu_percent(interval=1)
                
                memory = psutil.virtual_memory()
                self.stats['memory_percent'] = memory.percent
                self.stats['memory_used_mb'] = memory.used / (1024 * 1024)
                
                disk = psutil.disk_usage('/')
                self.stats['disk_usage_percent'] = disk.percent
                
                net_io_current = psutil.net_io_counters()
                self.stats['network_sent_mb'] = (net_io_current.bytes_sent - net_io_start.bytes_sent) / (1024 * 1024)
                self.stats['network_recv_mb'] = (net_io_current.bytes_recv - net_io_start.bytes_recv) / (1024 * 1024)
                
                for callback in self.callbacks:
                    try:
                        callback(self.stats)
                    except Exception as e:
                        print(f"Callback error: {e}")
                
                time.sleep(2)
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(5)
    
    def add_callback(self, callback):
        self.callbacks.append(callback)
    
    def remove_callback(self, callback):
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def get_system_info(self):
        return {
            'platform': f"{psutil.os_info.system} {psutil.os_info.release}",
            'processor': psutil.cpu_freq().current if psutil.cpu_freq() else "Unknown",
            'cpu_cores': psutil.cpu_count(),
            'total_memory_gb': psutil.virtual_memory().total / (1024 ** 3),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        }

class SystemMonitorGUI:
    def __init__(self, parent):
        self.parent = parent
        self.monitor = SystemMonitor()
        self.setup_ui()
        self.monitor.add_callback(self.update_display)
        self.monitor.start_monitoring()
    
    def setup_ui(self):
        self.window = tk.Toplevel(self.parent)
        self.window.title("System Monitor - CXA Crypto System")
        self.window.geometry("400x500")
        
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        info_frame = ttk.LabelFrame(main_frame, text="System Information")
        info_frame.pack(fill=tk.X, pady=5)
        
        system_info = self.monitor.get_system_info()
        for key, value in system_info.items():
            row = ttk.Frame(info_frame)
            row.pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(row, text=f"{key.replace('_', ' ').title()}:", width=20, anchor=tk.W).pack(side=tk.LEFT)
            ttk.Label(row, text=str(value), anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        stats_frame = ttk.LabelFrame(main_frame, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.stats_labels = {}
        stats = [
            ('cpu_percent', 'CPU Usage (%)'),
            ('memory_percent', 'Memory Usage (%)'),
            ('memory_used_mb', 'Memory Used (MB)'),
            ('disk_usage_percent', 'Disk Usage (%)'),
            ('network_sent_mb', 'Network Sent (MB)'),
            ('network_recv_mb', 'Network Received (MB)')
        ]
        
        for stat_key, stat_label in stats:
            row = ttk.Frame(stats_frame)
            row.pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(row, text=stat_label, width=20, anchor=tk.W).pack(side=tk.LEFT)
            value_label = ttk.Label(row, text="0", anchor=tk.W)
            value_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.stats_labels[stat_key] = value_label
        
        warning_frame = ttk.Frame(main_frame)
        warning_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(warning_frame, text="High resource usage may affect cryptographic operations.", 
                 foreground="orange", font=("Arial", 9)).pack()
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def update_display(self, stats):
        if not self.window.winfo_exists():
            return
            
        for stat_key, value in stats.items():
            if stat_key in self.stats_labels:
                formatted_value = f"{value:.2f}" if isinstance(value, float) else str(value)
                self.stats_labels[stat_key].config(text=formatted_value)
                
                if stat_key in ['cpu_percent', 'memory_percent'] and value > 80:
                    self.stats_labels[stat_key].config(foreground="red")
                elif stat_key in ['cpu_percent', 'memory_percent'] and value > 60:
                    self.stats_labels[stat_key].config(foreground="orange")
                else:
                    self.stats_labels[stat_key].config(foreground="black")
    
    def on_close(self):
        self.monitor.stop_monitoring()
        self.window.destroy()

system_monitor = SystemMonitor()