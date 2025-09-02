#!/bin/bash

# PhisGuard Development Runner
# Runs both Flask backend and Chrome extension simultaneously

echo "🎯 PhisGuard Development Server"
echo "================================"

# Check if we're in the right directory
if [ ! -f "app.py" ] || [ ! -f "package.json" ]; then
    echo "❌ Please run this script from the project root directory"
    exit 1
fi

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "🛑 Shutting down servers..."
    kill 0
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup EXIT INT TERM

# Build extension
echo "🔨 Building Chrome extension..."
npm run build:dev

if [ $? -ne 0 ]; then
    echo "❌ Extension build failed"
    exit 1
fi

echo "✅ Extension built successfully"

# Start Flask backend in background
echo "🚀 Starting Flask backend..."
python3 app.py &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 2

# Start extension file server
echo "📁 Starting extension file server..."
npx http-server dist -p 3000 -c-1 --cors &
EXTENSION_PID=$!

echo ""
echo "================================"
echo "🎉 Both servers are running!"
echo "📡 Backend API: http://localhost:5000"
echo "📁 Extension files: http://localhost:3000"
echo "🔧 Chrome extension: Load 'dist' folder in chrome://extensions"
echo "================================"
echo "Press Ctrl+C to stop both servers"
echo "================================"

# Wait for background processes
wait