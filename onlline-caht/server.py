# server.py
import asyncio
import websockets

clients = set()

async def handler(ws):
    clients.add(ws)
    try:
        async for msg in ws:
            # Broadcast to all clients except sender
            for c in clients:
                if c != ws:
                    await c.send(msg)
    finally:
        clients.remove(ws)

async def main():
    # Listen on all interfaces (0.0.0.0), port 8000
    async with websockets.serve(handler, "0.0.0.0", 8000):
        print("Server running on port 8000...")
        await asyncio.Future()  # Run forever

asyncio.run(main())
