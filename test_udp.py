import socks
import socket

# 1. 创建一个 SOCKS5 UDP socket
#    注意：一定要用 socks.socksocket 而不是 socket.socket
sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

# 2. 设置代理地址和端口
sock.set_proxy(
    proxy_type = socks.SOCKS5,
    addr       = "127.0.0.1",
    port       = 1080,
    rdns       = False,   # DNS 解析走不走代理，看情况 True/False 都行
)

# 3. 发包到目标 UDP 服务（例：1.2.3.4:9999）
sock.sendto(b"hello via socks5 udp", ("1.2.3.4", 9999))

# 4. 接收回应
data, peer = sock.recvfrom(2048)
print("from", peer, "got:", data)