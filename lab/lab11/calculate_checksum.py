def calculate_checksum(data):
    checksum = 0
    # 每次处理16位（两个字节）
    for i in range(0, len(data), 2):
        # 如果数据长度是奇数，最后一个字节补充 0x00
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        checksum += word
        # 处理溢出，将高位回卷加到低位
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    # 按位取反，生成校验和
    return ~checksum & 0xFFFF

# 重新组织完整的 ICMP 数据包内容
icmp_payload = [
    0x08, 0x00,  # Type + Code
    0x00, 0x00,  # Checksum placeholder（暂设为0）
    0x00, 0x01,  # Identifier（Big Endian）
    0x00, 0x20,  # Sequence Number（Big Endian）
    0x61, 0x62, 0x63, 0x64,  # Data部分
    0x65, 0x66, 0x67, 0x68,  # Data部分继续
    0x69, 0x6A, 0x6B, 0x6C,  # Data部分继续
    0x6D, 0x6E, 0x6F, 0x70,  # Data部分继续
    0x71, 0x72, 0x73, 0x74,  # Data部分继续
    0x75, 0x76, 0x77, 0x61,  # Data部分继续
    0x62, 0x63, 0x64, 0x65,  # Data部分继续
    0x66, 0x67, 0x68, 0x69,  # Data部分最后。共计 35字节，需要补充。
    0x00                   # 补齐为偶数字节，总字节数为36。
]

# 计算校验和
calculated_checksum = calculate_checksum(icmp_payload)
print(f"Calculated checksum: {hex(calculated_checksum)}")