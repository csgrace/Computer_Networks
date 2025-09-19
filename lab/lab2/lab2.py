
class Main:
    def is_valid_ip(self, ip: str) -> bool:
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit() or not (0 <= int(part) <= 255):
                    return False

            return True
        except ValueError:
            return False

    def is_valid_subnet_mask(self, mask: str) -> bool:
        try:
            parts = mask.split('.')
            if len(parts) != 4:
                return False

            # 检查每部分是否为数字且范围在0到255
            for part in parts:
                if not part.isdigit() or not (0 <= int(part) <= 255):
                    return False

            # 转换为二进制并验证是否是有效的连续1和0
            mask_binary = "".join([bin(int(octet))[2:].zfill(8) for octet in parts])
            if "01" in mask_binary:  # 子网掩码中不允许出现“01”
                return False

            return True
        except ValueError:
            return False

    def calculate_network_host_id(self, ip: str, mask: str):
        # 将IP和子网掩码转换为二进制格式
        ip_parts = ip.split('.')
        mask_parts = mask.split('.')
        network_id_parts = []

        for ip_part, mask_part in zip(ip_parts, mask_parts):
            # 按位与计算网络ID
            network_id_parts.append(str(int(ip_part) & int(mask_part)))

        # 网络ID
        network_id = ".".join(network_id_parts)

        # 主机ID（计算IP地址减去网络ID）
        host_id = int(ip_parts[-1]) & ~int(mask_parts[-1])

        return network_id, host_id

    def run(self):
        while True:
            try:
                user_input = input("Input: ").strip()
                ip, mask = user_input.split()

                if not self.is_valid_ip(ip):
                    print("IP address illegal")
                    continue

                if not self.is_valid_subnet_mask(mask):
                    print("subnet mask illegal")
                    continue

                network_id, host_id = self.calculate_network_host_id(ip, mask)
                print(f"network ID: {network_id}, host ID: {host_id}")

            except KeyboardInterrupt:
                print("\n exit")
                break

if __name__ == "__main__":
    main_instance = Main()
    main_instance.run()