# external/signaling_server.py

import asyncio
import websockets
import json

# 연결된 클라이언트 관리
clients = []

async def signaling_handler(websocket, path):
    global clients
    clients.append(websocket)
    try:
        async for message in websocket:
            data = json.loads(message)
            print(f"Received: {data}")

            # 다른 클라이언트에게 메시지 전달
            for client in clients:
                if client != websocket:
                    await client.send(json.dumps(data))
    except websockets.exceptions.ConnectionClosed:
        print("Connection closed")
    finally:
        clients.remove(websocket)

# WebSocket 서버 실행
async def main():
    async with websockets.serve(signaling_handler, "localhost", 8765):
        print("Signaling server started on ws://localhost:8765")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
