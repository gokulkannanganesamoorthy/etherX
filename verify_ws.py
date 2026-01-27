import asyncio
import websockets
import json

async def test_ws():
    uri = "ws://localhost:8000/ws"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Waiting for messages...")
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    print(f"Received: {message[:100]}...")
                except asyncio.TimeoutError:
                    print("No message received in 5 seconds.")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_ws())
