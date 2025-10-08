import socket
def echo():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 5555))
    sock.listen(10)
    sock.settimeout(0.5)

    running = True

    while running:
        try:
            conn, address = sock.accept()
            while True:
                data = conn.recv(2048)
                if data == b'quit':
                    conn.close()
                    running = False  # 收到 quit 命令就退出主循环
                    break
                elif data and data != b'exit':
                    conn.send(data)
                    print(data)
                else:
                    conn.close()
                    break
        except socket.timeout:
            continue
    sock.close()  # 释放端口资源
    print("Server exited gracefully.")

if __name__ == "__main__":
 try:
    echo()
 except KeyboardInterrupt:
    pass