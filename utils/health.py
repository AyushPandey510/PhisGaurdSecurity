import time
from datetime import datetime
from utils.cache import get_cache
from utils.logger import get_security_logger

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

class HealthChecker:
    """Comprehensive health checker for the application"""

    def __init__(self):
        self.start_time = time.time()
        self.cache = get_cache()
        self.logger = get_security_logger()

    def get_system_health(self):
        """Get system-level health metrics"""
        if not PSUTIL_AVAILABLE:
            return {"error": "System metrics unavailable - psutil not installed"}

        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "percent": psutil.virtual_memory().percent
                },
                "disk": {
                    "total": psutil.disk_usage('/').total,
                    "free": psutil.disk_usage('/').free,
                    "percent": psutil.disk_usage('/').percent
                }
            }
        except Exception as e:
            self.logger.log_error("HealthCheckError", f"Failed to get system health: {str(e)}")
            return {"error": "Unable to retrieve system health"}

    def get_application_health(self):
        """Get application-level health metrics"""
        try:
            uptime = time.time() - self.start_time

            # Clean up expired cache entries
            expired_count = self.cache.cleanup()

            return {
                "uptime_seconds": uptime,
                "cache_entries": len(self.cache.cache),
                "expired_cache_cleaned": expired_count,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            self.logger.log_error("HealthCheckError", f"Failed to get application health: {str(e)}")
            return {"error": "Unable to retrieve application health"}

    def check_dependencies(self):
        """Check if critical dependencies are available"""
        dependencies = {
            "flask": False,
            "requests": False,
            "psutil": False
        }

        try:
            import flask
            dependencies["flask"] = True
        except ImportError:
            pass

        try:
            import requests
            dependencies["requests"] = True
        except ImportError:
            pass

        dependencies["psutil"] = PSUTIL_AVAILABLE

        return dependencies

    def get_full_health_report(self):
        """Get comprehensive health report"""
        return {
            "status": "healthy",
            "service": "phisguard-backend",
            "timestamp": datetime.utcnow().isoformat(),
            "system": self.get_system_health(),
            "application": self.get_application_health(),
            "dependencies": self.check_dependencies()
        }

# Global health checker instance
health_checker = HealthChecker()

def get_health_checker():
    """Get the global health checker instance"""
    return health_checker