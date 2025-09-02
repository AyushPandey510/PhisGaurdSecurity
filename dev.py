#!/usr/bin/env python3
"""
PhisGuard Development Server
Runs both Flask backend and serves Chrome extension files simultaneously
"""

import subprocess
import sys
import os
import signal
import time
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import flask
        import flask_cors
        import flask_limiter
        import flask_talisman
    except ImportError as e:
        print(f"❌ Missing Python dependency: {e}")
        print("Run: pip install -r requirements.txt")
        return False

    # Check if npm dependencies are installed
    if not Path("node_modules").exists():
        print("❌ Node.js dependencies not found")
        print("Run: npm install")
        return False

    return True

def start_backend():
    """Start the Flask backend server"""
    print("🚀 Starting Flask backend server...")
    return subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

def start_extension_server():
    """Start the extension file server"""
    print("📁 Starting extension file server...")
    return subprocess.Popen(
        ["npx", "http-server", "dist", "-p", "3000", "-c-1", "--cors"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

def build_extension():
    """Build the Chrome extension"""
    print("🔨 Building Chrome extension...")
    result = subprocess.run(
        ["npm", "run", "build:dev"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"❌ Build failed: {result.stderr}")
        return False

    print("✅ Extension built successfully")
    return True

def main():
    """Main development server function"""
    print("🎯 PhisGuard Development Server")
    print("=" * 40)

    # Check if we're in the right directory
    if not Path("app.py").exists() or not Path("package.json").exists():
        print("❌ Please run this script from the project root directory")
        sys.exit(1)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Build extension first
    if not build_extension():
        sys.exit(1)

    # Start both servers
    backend_process = start_backend()
    extension_process = start_extension_server()

    print("\n" + "=" * 40)
    print("🎉 Both servers are running!")
    print("📡 Backend API: http://localhost:5000")
    print("📁 Extension files: http://localhost:3000")
    print("🔧 Chrome extension: Load 'dist' folder in chrome://extensions")
    print("=" * 40)
    print("Press Ctrl+C to stop both servers")
    print("=" * 40)

    def signal_handler(signum, frame):
        """Handle shutdown signals"""
        print("\n🛑 Shutting down servers...")
        backend_process.terminate()
        extension_process.terminate()

        # Wait for processes to finish
        try:
            backend_process.wait(timeout=5)
            extension_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend_process.kill()
            extension_process.kill()

        print("✅ Servers stopped")
        sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Monitor processes
    try:
        while True:
            if backend_process.poll() is not None:
                print("❌ Backend server crashed!")
                break
            if extension_process.poll() is not None:
                print("❌ Extension server crashed!")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()