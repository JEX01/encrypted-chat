# client.py
import asyncio
import websockets

async def main():
    uri = "ws://YOUR_PUBLIC_URL:8000"  # Replace with LocalTunnel/ngrok URL
    async with websockets.connect(uri) as ws:

        async def send_loop():
            while True:
                msg = input()
                await ws.send(msg)

        async def recv_loop():
            while True:
                print(await ws.recv())

        await asyncio.gather(send_loop(), recv_loop())

asyncio.run(main())

