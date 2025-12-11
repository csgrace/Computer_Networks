import socket
import struct
import argparse
import sys
import psutil
import time
import ipaddress
import os

class PingTool:
    # Define constants
    IPv4 = 4
    IPv6 = 6

    def validate_ip(self, ip):
        """
        Validate IP address and return version
        
        Args:
            ip (str): IP address to validate
            
        Returns:
            int: IP version (4 or 6) or None if invalid
        """
        # TODO: Implement IP validation
        try:
            addr = ipaddress.ip_address(ip)
            return self.IPv6 if isinstance(addr, ipaddress.IPv6Address) else self.IPv4
        except ValueError:
            return None


    def is_unicast_address(self, ip, ip_version):
        """
        Check if the IP address is an unicast address

        Args:
            ip (str): IP address to check
            ip_version (int): IP version (4 or 6)

        Returns:
            bool: True if it's an unicast address, False otherwise
        """
        # TODO: Implement unicast address check
        try:
            if ip_version == self.IPv4:
                addr = ipaddress.IPv4Address(ip)
                # Valid unicast: 1.0.0.0 to 223.255.255.255 (exclude 0.0.0.0/8, 224.0.0.0/4, 255.255.255.255)
                return (int(addr) >= int(ipaddress.IPv4Address("1.0.0.0"))
                        and int(addr) <= int(ipaddress.IPv4Address("223.255.255.255")))
            else:
                addr = ipaddress.IPv6Address(ip)
                # Global unicast 2000::/3 (2000:: - 3fff:ffff:... per assignment)
                return ipaddress.IPv6Network("2000::/3").supernet(new_prefix=3).__contains__(
                    addr) or ipaddress.IPv6Network("2000::/3").__contains__(addr)
        except ValueError:
            return False


    def is_multicast_address(self, ip, ip_version):
        """
        Check if the IP address is a multicast address
        
        Args:
            ip (str): IP address to check
            ip_version (int): IP version (4 or 6)
            
        Returns:
            bool: True if it's a multicast address, False otherwise
        """
        # TODO: Implement multicast address check
        try:
            if ip_version == self.IPv4:
                addr = ipaddress.IPv4Address(ip)
                return ipaddress.IPv4Network("224.0.0.0/4").__contains__(addr)
            else:
                addr = ipaddress.IPv6Address(ip)
                return str(addr).lower().startswith("ff")
        except ValueError:
            return False



    def ipv4_multicast_to_mac(self, ip):
        """
        Convert IPv4 multicast address to multicast MAC address
        
        Args:
            ip (str): IPv4 multicast address
            
        Returns:
            str: Multicast MAC address
            
        Raises:
            ValueError: If the IP is not a valid IPv4 multicast address
        """
        # TODO: Implement IPv4 multicast address to MAC conversion
        if not self.is_multicast_address(ip, self.IPv4):
            raise ValueError("Not a valid IPv4 multicast address")
        maddr = int(ipaddress.IPv4Address(ip))
        low_23 = maddr & 0x7FFFFF
        mac = [
            0x01, 0x00, 0x5e,
            (low_23 >> 16) & 0x7F,
            (low_23 >> 8) & 0xFF,
            low_23 & 0xFF
        ]
        return ":".join(f"{b:02x}" for b in mac)


    def ipv6_multicast_to_mac(self, ip):
        """
        Convert IPv6 multicast address to multicast MAC address
        
        Args:
            ip (str): IPv6 multicast address
            
        Returns:
            str: Multicast MAC address
            
        Raises:
            ValueError: If the IP is not a valid IPv6 multicast address
        """
        # TODO: Implement IPv6 multicast address to MAC conversion
        if not self.is_multicast_address(ip, self.IPv6):
            raise ValueError("Not a valid IPv6 multicast address")
        packed = socket.inet_pton(socket.AF_INET6, ip)
        last32 = packed[-4:]
        mac = [0x33, 0x33, last32[0], last32[1], last32[2], last32[3]]
        return ":".join(f"{b:02x}" for b in mac)

    def get_interface_by_ip(self, target_ip):
        """
        Find network interface by IP address using psutil
        
        Args:
            target_ip (str): Target IP address
            
        Returns:
            str: Interface name or None if not found
        """
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == target_ip:
                    return iface
                if addr.family == socket.AF_INET6:
                    a = addr.address.split("%")[0]
                    if a == target_ip:
                        return iface
        return None

    def create_raw_socket(self, ip_version, is_multicast=False):
        """
        Create raw socket
        
        Args:
            ip_version (int): IP version (4 or 6)
            is_multicast (bool): Whether it's for multicast communication
            
        Returns:
            socket: Raw socket object
        """
        try:
            if ip_version == self.IPv6:
                # Create IPv6 raw socket
                sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
                # Allow IPv6 socket to receive its own multicast packets
                if is_multicast:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
            else:
                # Create IPv4 raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                # Allow IPv4 socket to send multicast packets
                if is_multicast:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            return sock
        except PermissionError:
            print("Error: Administrator privileges required to create raw socket")
            sys.exit(1)
        except Exception as e:
            print(f"Error creating socket: {e}")
            sys.exit(1)

    def _internet_checksum(self, data):
        # Standard one's complement 16-bit checksum
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff

    def _icmpv6_checksum(self, src_ip, dst_ip, icmp_payload):
        # IPv6 pseudo header: src(16) dst(16) length(4) zero(3) next header(1)
        src = socket.inet_pton(socket.AF_INET6, src_ip)
        dst = socket.inet_pton(socket.AF_INET6, dst_ip)
        length = struct.pack("!I", len(icmp_payload))
        pseudo = src + dst + length + b'\x00' * 3 + struct.pack("!B", socket.IPPROTO_ICMPV6)
        return self._internet_checksum(pseudo + icmp_payload)

    def send_ipv4_unicast(self, src_addr, dst_addr, count):
        """
        Send IPv4 unicast ICMP echo request packets
        
        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination IP address
            count (int): Number of packets to send
        """
        try:
            sock = self.create_raw_socket(self.IPv4)
            if src_addr:
                sock.bind((src_addr, 0))
            for i in range(count):
                # TODO：Implement IPv4 unicast packet sending
                # Construct ICMP Echo Request packet
                icmp_type = 8
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = 0x1234
                # NOTE: please do not modify the value of 'icmp_seq',for the values of other fields, please specify them according to the Protocol.
                icmp_seq = i
                # Construct ICMP header (without checksum)
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                payload = b"CS305Ping-" + struct.pack("!d", time.time())
                # Calculate checksum
                icmp_checksum = self._internet_checksum(header + payload)
                # Reconstruct ICMP header with checksum and send
                packet = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + payload
                sock.sendto(packet, (dst_addr, 0))
                # Note: please do not remove print code, as it is used to validate the checksum of ICMP you calculated
                print(f"Sent ICMPv4 Echo Request to {dst_addr} (Checksum: {icmp_checksum:04x})- Packet {i + 1}")
                time.sleep(1)

            sock.close()
        except Exception as e:
            print(f"Error sending IPv4 unicast packets: {e}")
            import traceback
            traceback.print_exc()

    def send_ipv6_unicast(self, src_addr, dst_addr, count):
        """
        Send IPv6 unicast ICMPv6 echo request packets
        
        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination IP address
            count (int): Number of packets to send
        """
        try:
            sock = self.create_raw_socket(self.IPv6)
            if src_addr:
                # sock.bind((src_addr, 0))
                sock.bind((src_addr, 0, 0, 0))
            # TODO：Implement IPv6 unicast packet sending
            for i in range(count):
                # Construct ICMPv6 Echo Request packet
                icmp_type = 128  # Echo Request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id =  0x1234
                # NOTE: please do not modify the value of 'icmp_seq',for the values of other fields, please specify them according to the Protocol.
                icmp_seq = i

                # Construct ICMPv6 header (without checksum)
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                payload = b"CS305Ping6-" + struct.pack("!d", time.time())

                # For ICMPv6, checksum calculation includes IPv6 pseudo header
                # Calculate checksum
                icmp_checksum = self._icmpv6_checksum(src_addr if src_addr else "::1", dst_addr, header + payload)

                # Reconstruct ICMP header with checksum and send
                packet = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + payload
                sock.sendto(packet, (dst_addr, 0, 0, 0))

                # Note: please do not remove print code, as it is used to validate the checksum of ICMP you calculated
                print(f"Sent ICMPv6 Echo Request to {dst_addr} (Checksum: {icmp_checksum:04x})- Packet {i + 1}")
                time.sleep(1)

            sock.close()
        except Exception as e:
            print(f"Error sending IPv6 unicast packets: {e}")
            import traceback
            traceback.print_exc()

    def send_ipv4_multicast(self, src_addr, dst_addr, count):
        """
        Send IPv4 multicast ICMP echo request packets
        
        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination multicast IP address
            count (int): Number of packets to send
        """
        try:
            # Get multicast MAC address,and print it!
            # Note: You may don't need use the mac address to send multicast packets by socket,
            # but please do not remove print code, as it is used to validate the multicast MAC address you implemented
            multicast_mac = self.ipv4_multicast_to_mac(dst_addr)
            print(f"Multicast MAC Address: {multicast_mac}")
            
            # Get network interface
            iface = self.get_interface_by_ip(src_addr)
            if not iface:
                print(f"Warning: Could not find interface for IP {src_addr}")
            
            sock = self.create_raw_socket(self.IPv4, is_multicast=True)
            if src_addr:
                sock.bind((src_addr, 0))
            # TODO：Implement IPv4 multicast packet sending
            for i in range(count):
                # Construct ICMP Echo Request packet
                icmp_type = 8
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = 0x1234
                # NOTE: please do not modify the value of 'icmp_seq',for the values of other fields, please specify them according to the Protocol.
                icmp_seq = i

                payload = b"CS305MIPv4-" + struct.pack("!d", time.time())
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

                # Calculate checksum
                icmp_checksum = self._internet_checksum(header + payload)

                # Reconstruct ICMP header with checksum and send
                packet = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + payload
                sock.sendto(packet, (dst_addr, 0))

                # Note: please do not remove print code, as it is used to validate the checksum of ICMP you calculated
                print(f"Sent ICMP Echo Request to {dst_addr} (MAC: {multicast_mac} - Checksum: {icmp_checksum:04x}) - Packet {i+1}")
                time.sleep(1)
            sock.close()
        except Exception as e:
            print(f"Error sending IPv4 multicast packets: {e}")
            import traceback
            traceback.print_exc()

    def send_ipv6_multicast(self, src_addr, dst_addr, count):
        """
        Send IPv6 multicast ICMPv6 echo request packets
        
        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination multicast IP address
            count (int): Number of packets to send
        """
        try:
            # Get multicast MAC address,and print it!
            # Note: You may don't need use the mac address to send multicast packets by socket,
            # but please do not remove print code, as it is used to validate the multicast MAC address you implemented
            multicast_mac = self.ipv6_multicast_to_mac(dst_addr)
            print(f"Multicast MAC Address: {multicast_mac}")

            sock = self.create_raw_socket(self.IPv6, is_multicast=True)
            if src_addr:
                sock.bind((src_addr, 0))
            
            # Set IPv6 multicast hop limit
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 32)
            except Exception as e:
                print(f"Warning: Failed to set IPV6_MULTICAST_HOPS: {e}")
                # Try alternative method
                try:
                    sock.setsockopt(socket.SOL_IPV6, socket.IPV6_MULTICAST_HOPS, struct.pack('i', 32))
                except Exception as e2:
                    print(f"Warning: Alternative method also failed: {e2}")
            # TODO：Implement IPv6 multicast packet sending
            for i in range(count):
                # Construct ICMPv6 Echo Request packet
                icmp_type = 128
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = 0x1234
                # NOTE: please do not modify the value of 'icmp_seq',for the values of other fields, please specify them according to the Protocol.
                icmp_seq = i

                payload = b"CS305MIPv6-" + struct.pack("!d", time.time())
                header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

                # For ICMPv6, checksum calculation includes IPv6 pseudo header
                # Calculate checksum
                src_for_checksum = src_addr if src_addr else "::1"
                icmp_checksum = self._icmpv6_checksum(src_for_checksum, dst_addr, header + payload)

                # Reconstruct ICMP header with checksum and send
                packet = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + payload
                sock.sendto(packet, (dst_addr, 0, 0, 0))

                # Note: please do not remove print code, as it is used to validate the checksum of ICMP you calculated
                print(
                    f"Sent ICMP Echo Request to {dst_addr} (MAC: {multicast_mac} - Checksum: {icmp_checksum:04x}) - Packet {i + 1}")
                time.sleep(1)

            sock.close()
        except Exception as e:
            print(f"Error sending IPv6 multicast packets: {e}")
            import traceback
            traceback.print_exc()

    def calculate_checksum(self, data):
        """
        Calculate checksum of ICMP packet
        
        Args:
            data (bytes): Data（ICMP_HEADER+ICMP_DATA  OR  pseudo_header+ICMPv6_Header+ICMPv6_DATA） to calculate checksum for
            
        Returns:
            int: Calculated checksum
        """
        #TODO: Implement checksum calculation
        return self._internet_checksum(data)



    def run(self, src_addr, dst_addr, count, mode):
        """
        Main run function
        
        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination IP address
            count (int): Number of packets to send
            mode (str): Send mode (unicast or multicast)
        """
        # Validate destination address
        ip_version = self.validate_ip(dst_addr)
        if ip_version is None:
            print(f"Error: Invalid IP address {dst_addr}")
            return

        # Validate source address (if provided)
        if src_addr:
            src_version = self.validate_ip(src_addr)
            if src_version is None:
                print(f"Error: Invalid source IP address {src_addr}")
                return
            if src_version != ip_version:
                print("Error: Source and destination IP versions must match")
                return

        # If multicast mode, validate multicast address
        if mode == "multicast":
            if not self.is_multicast_address(dst_addr, ip_version):
                print(f"Error: {dst_addr} is not a valid multicast address")
                if ip_version == self.IPv4:
                    print("IPv4 multicast addresses should be in range 224.0.0.0 to 239.255.255.255")
                else:
                    print("IPv6 multicast addresses should start with FF00::/8 prefix")
                return
        # If unicast mode, validate unicast address
        if mode == "unicast":
            if not self.is_unicast_address(dst_addr, ip_version):
                print(f"Error: {dst_addr} is not a valid unicast address")
                if ip_version == self.IPv4:
                    print("IPv4 unicast addresses should be in range 1.0.0.0 to 223.255.255.255")
                else:
                    print("IPv6 unicast addresses should within the range from 2000:: to 3FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")
                return

        print(f"Pinging {dst_addr} with {count} packets:")

        # Send packets based on address type and mode
        if ip_version == self.IPv4:
            if mode == "unicast":
                self.send_ipv4_unicast(src_addr, dst_addr, count)
            else:  # multicast
                self.send_ipv4_multicast(src_addr, dst_addr, count)
        else:  # IPv6
            if mode == "unicast":
                self.send_ipv6_unicast(src_addr, dst_addr, count)
            else:  # multicast
                self.send_ipv6_multicast(src_addr, dst_addr, count)


def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser(description="Python Ping Tool with ICMP Multicast Support")
    parser.add_argument("destination", help="Destination IP address")
    parser.add_argument("-s", "--source", help="Source IP address", default="")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to send", default=4)
    parser.add_argument("-m", "--mode", choices=["unicast", "multicast"],
                        help="Send mode (unicast or multicast)", default="unicast")

    args = parser.parse_args()

    # Create PingTool instance
    ping_tool = PingTool()
    # Run
    ping_tool.run(args.source, args.destination, args.count, args.mode)


if __name__ == "__main__":
    main()