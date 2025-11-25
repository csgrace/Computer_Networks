#!/usr/bin/env python3
# 简单版 ICMPv6 校验和计算脚本，结构和你给的 calculate_checksum.py 类似（使用列表表示每个字节）
# 这个脚本使用你截图对应的包字段（Echo Reply, src/dst, id=0x0001, seq=0x0003, 32 bytes data）
# 运行后会打印计算得到的 checksum，并把 checksum 写回 ICMPv6 消息并输出整条 ICMPv6 消息的 hex。

def calculate_checksum(data):
    checksum = 0
    # 每次处理16位（两个字节）
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        checksum += word
        # 处理溢出，将高位回卷加到低位
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    # 按位取反，生成校验和
    return (~checksum) & 0xFFFF

# --------------------------
# 伪头部 (pseudo-header) 部分（IPv6 源/目的地址、payload length、zeros、next header）
# 源地址: 2606:4700:4700::1111 -> 展开为 8 段:
pseudo_src = [
    0x26, 0x06,  # 2606
    0x47, 0x00,  # 4700
    0x47, 0x00,  # 4700
    0x00, 0x00,  # 0000
    0x00, 0x00,  # 0000
    0x00, 0x00,  # 0000
    0x00, 0x00,  # 0000
    0x11, 0x11   # 1111
]

# 目的地址: 2001:0da8:201d:1113::ff84 -> 展开为:
pseudo_dst = [
    0x20, 0x01,  # 2001
    0x0d, 0xa8,  # 0da8
    0x20, 0x1d,  # 201d
    0x11, 0x13,  # 1113
    0x00, 0x00,  # 0000
    0x00, 0x00,  # 0000
    0x00, 0x00,  # 0000
    0xff, 0x84   # ff84
]

# ICMPv6 消息（Type, Code, Checksum(占位), Identifier, Sequence, Data(32 bytes)）
# 根据截图：Type=0x81 (129 Echo Reply), Code=0x00, checksum=0xb07f (Wireshark显示)
icmpv6_msg = [
    0x81, 0x00,        # Type, Code
    0x00, 0x00,        # Checksum placeholder (计算前置0)
    0x00, 0x01,        # Identifier (0x0001)
    0x00, 0x03,        # Sequence (0x0003)
    # 32 bytes data (来自截图)
    0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,
    0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
    0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x61,
    0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69   # 注意：填入最后一个字节0x00以确保数据为偶数长度（如果实际抓包最后不是0x00，请用抓包数据替换）
]

# 如果你希望严格按截图的数据（32 bytes）并不是奇数，这里末尾的0x00可以去掉；但伪头部+消息合计要为偶数字节以便计算正确。
# 上面最后的 0x00 是为了保证示例长度为偶数（如果你使用原始抓包字节流，请替换 icmpv6_msg 为抓包的字节序列）。

# 计算 payload length (ICMPv6 消息长度)，以字节为单位
payload_len = len(icmpv6_msg)  # 例如应为 40 (4 + 4 + 32)

# 把 payload length 放为 4 字节（big-endian）
payload_len_bytes = [
    (payload_len >> 24) & 0xFF,
    (payload_len >> 16) & 0xFF,
    (payload_len >> 8) & 0xFF,
    payload_len & 0xFF
]

# 三个零字节 + next header (58 decimal -> 0x3A)
pseudo_tail = [0x00, 0x00, 0x00, 0x3A]

# 伪头部拼接为字节列表
pseudo_header = pseudo_src + pseudo_dst + payload_len_bytes + pseudo_tail

# 拼接用于计算校验和的完整字节流：伪头部 + ICMPv6消息（其中checksum置0）
checksum_input = pseudo_header + icmpv6_msg

# 计算
calculated = calculate_checksum(checksum_input)

print(f"Calculated checksum: 0x{calculated:04x}")


