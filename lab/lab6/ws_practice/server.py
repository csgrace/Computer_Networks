# server.py
import asyncio
import sys
import websockets
import traceback

class DanmakuServer:
    def __init__(self):
        self.clients = set()

    async def handler(self, websocket, path=None):
        self.clients.add(websocket)
        print(f"+ client connected, total: {len(self.clients)}")
        try:
            async for msg in websocket:
                print(f"recv: {msg!r}")
                to_remove = set()
                # 广播：直接尝试发送，发送失败或连接已关闭就移除
                for ws in list(self.clients):
                    if ws is websocket:
                        # 可选择是否广播给自己；这里仍广播给自己
                        pass
                    try:
                        # 直接发送（不要依赖 ws.open）
                        await ws.send(msg)
                        print("  sent -> a client")
                    except Exception as e:
                        # 发送失败就移除该客户端
                        print("  send failed, will remove client:", repr(e))
                        # 打印 traceback 有助于进一步诊断
                        traceback.print_exc()
                        to_remove.add(ws)

                for ws in to_remove:
                    try:
                        self.clients.discard(ws)
                    except Exception:
                        pass
        except websockets.exceptions.ConnectionClosedOK:
            # 正常关闭
            pass
        except Exception as e:
            print("handler exception:", e)
            traceback.print_exc()
        finally:
            # 最终移除当前 websocket（已断开）
            self.clients.discard(websocket)
            print(f"- client disconnected, total: {len(self.clients)}")


async def main():
    server = DanmakuServer()
    print("listening ws://0.0.0.0:8765")
    async with websockets.serve(server.handler, '0.0.0.0', 8765):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("server stopped")
