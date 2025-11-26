import socket
import struct
import time
import argparse
import sys
import psutil
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
            return self.IPv4 if addr.version == 4 else self.IPv6
        except Exception:
            return None

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
            addr = ipaddress.ip_address(ip)
            return addr.is_multicast
        except Exception:
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
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            raise ValueError("Invalid IPv4 address")

        if not addr.is_multicast:
            raise ValueError("IPv4 address is not multicast")

        ip_int = int(addr)
        # RFC mapping: 01:00:5e:0xxxxxxx:xxxxxxxx:xxxxxxxx
        # take lower 23 bits of IP address
        b1 = 0x01
        b2 = 0x00
        b3 = 0x5e
        b4 = (lower23 >> 16) & 0x7F
        b5 = (lower23 >> 8) & 0xFF
        b6 = lower23 & 0xFF
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (b1, b2, b3, b4, b5, b6)


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
        try:
            addr = ipaddress.IPv6Address(ip)
        except Exception:
            raise ValueError("Invalid IPv6 address")

        if not addr.is_multicast:
            raise ValueError("IPv6 address is not multicast")

        ip_int = int(addr)
        # IPv6 multicast to MAC: 33:33:xx:xx:xx:xx -> low-order 32 bits of IPv6 address
        lower32 = ip_int & 0xFFFFFFFF
        b1 = 0x33
        b2 = 0x33
        b3 = (lower32 >> 24) & 0xFF
        b4 = (lower32 >> 16) & 0xFF
        b5 = (lower32 >> 8) & 0xFF
        b6 = lower32 & 0xFF
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (b1, b2, b3, b4, b5, b6)

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
                # check both IPv4 and IPv6 families
                if addr.family == socket.AF_INET and addr.address == target_ip:
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

    def send_ipv4_unicast(self, src_addr, dst_addr, count):
        """
        Send IPv4 unicast ICMP packets

        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination IP address
            count (int): Number of packets to send
        """
        try:
            sock = self.create_raw_socket(self.IPv4)
            if src_addr:
                sock.bind((src_addr, 0))
            # TODO：Implement IPv4 unicast packet sending

            pid = os.getpid() & 0xFFFF
            seq = 1
            payload = b'PythonPingTool'  # simple payload

            for i in range(count):
                # ICMP header: type(1), code(1), checksum(2), id(2), seq(2)
                icmp_type = 8  # Echo Request
                icmp_code = 0
                chksum = 0
                header = struct.pack('!BBHHH', icmp_type, icmp_code, chksum, pid, seq)
                packet = header + payload
                chksum = self.calculate_checksum(packet)
                header = struct.pack('!BBHHH', icmp_type, icmp_code, chksum, pid, seq)
                packet = header + payload
                sock.sendto(packet, (dst_addr, 0))
                print(f"Sent IPv4 ICMP Echo Request to {dst_addr}, seq={seq}")
                seq += 1
                time.sleep(1)

            sock.close()
        except Exception as e:
            print(f"Error sending IPv4 unicast packets: {e}")
            import traceback
            traceback.print_exc()

    def send_ipv6_unicast(self, src_addr, dst_addr, count):
        """
        Send IPv6 unicast ICMP packets

        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination IP address
            count (int): Number of packets to send
        """
        try:
            sock = self.create_raw_socket(self.IPv6)
            if src_addr:
            # TODO：Implement IPv6 unicast packet sending
                try:
                    sock.bind((src_addr, 0))
                except Exception:
                    # try binding without scope
                    sock.bind((src_addr.split('%')[0], 0))

            pid = os.getpid() & 0xFFFF
            seq = 1
            payload = b'PythonPingTool-IPv6'

            for i in range(count):
                icmp_type = 128  # ICMPv6 Echo Request
                icmp_code = 0
                chksum = 0
                header = struct.pack('!BBHHH', icmp_type, icmp_code, chksum, pid, seq)
                packet = header + payload
                # For ICMPv6 the kernel typically calculates checksum for raw socket.
                # But we'll still compute a checksum of the ICMPv6 message alone as placeholder 0.
                # Many systems expect 0 so kernel adds correct pseudo header checksum.
                # Set checksum field to 0
                header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, pid, seq)
                packet = header + payload
                # sendto for IPv6: address tuple is (addr, port, flowinfo, scopeid)
                sock.sendto(packet, (dst_addr, 0, 0, 0))
                print(f"Sent IPv6 ICMPv6 Echo Request to {dst_addr}, seq={seq}")
                seq += 1
                time.sleep(1)


            sock.close()
        except Exception as e:
            print(f"Error sending IPv6 unicast packets: {e}")
            import traceback
            traceback.print_exc()

    def send_ipv4_multicast(self, src_addr, dst_addr, count):
        """
        Send IPv4 multicast ICMP packets

        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination multicast IP address
            count (int): Number of packets to send
        """
        try:
            # Get multicast MAC address
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

            # Set multicast TTL (how far packets propagate)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 1))
            except Exception:
                # fallback to integer packing
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

            # If available set outgoing interface for multicast
            if src_addr:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src_addr))
                except Exception as e:
                    print(f"Warning: Could not set IP_MULTICAST_IF: {e}")

            # send ICMP echo request to multicast group
            pid = os.getpid() & 0xFFFF
            seq = 1
            payload = b'PythonMulticastPing'

            for i in range(count):
                icmp_type = 8  # Echo Request
                icmp_code = 0
                chksum = 0
                header = struct.pack('!BBHHH', icmp_type, icmp_code, chksum, pid, seq)
                packet = header + payload
                chksum = self.calculate_checksum(packet)
                header = struct.pack('!BBHHH', icmp_type, icmp_code, chksum, pid, seq)
                packet = header + payload
                sock.sendto(packet, (dst_addr, 0))
                print(f"Sent IPv4 ICMP Multicast Echo Request to {dst_addr}, seq={seq}")
                seq += 1
                time.sleep(1)
            sock.close()
        except Exception as e:
            print(f"Error sending IPv4 multicast packets: {e}")
            import traceback
            traceback.print_exc()

    def send_ipv6_multicast(self, src_addr, dst_addr, count):
        """
        Send IPv6 multicast ICMP packets

        Args:
            src_addr (str): Source IP address
            dst_addr (str): Destination multicast IP address
            count (int): Number of packets to send
        """
        try:
            # Get multicast MAC address
            multicast_mac = self.ipv6_multicast_to_mac(dst_addr)
            print(f"Multicast MAC Address: {multicast_mac}")

            # new
            iface = None
            if src_addr:
                iface = self.get_interface_by_ip(src_addr)
            # new

            sock = self.create_raw_socket(self.IPv6, is_multicast=True)
            if src_addr:
                try:
                    sock.bind((src_addr, 0))
                except Exception:
                    sock.bind((src_addr.split('%')[0], 0))

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
            # TODO：Implement IPv4 multicast packet sending
            # If we know the interface name, set IPV6_MULTICAST_IF
            if iface:
                try:
                    if_index = socket.if_nametoindex(iface)
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack('I', if_index))
                except Exception as e:
                    print(f"Warning: Could not set IPV6_MULTICAST_IF: {e}")
                    if_index = 0
            else:
                if_index = 0

            pid = os.getpid() & 0xFFFF
            seq = 1
            payload = b'PythonIPv6Multicast'

            for i in range(count):
                icmp_type = 128  # ICMPv6 Echo Request
                icmp_code = 0
                header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, pid, seq)
                packet = header + payload
                # let kernel compute ICMPv6 checksum
                sock.sendto(packet, (dst_addr, 0, 0, if_index))
                print(f"Sent IPv6 ICMPv6 Multicast Echo Request to {dst_addr}, seq={seq}")
                seq += 1
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
            data (bytes): header + data to calculate checksum for ICMP packet

        Returns:
            int: Calculated checksum
        """
        #TODO: Implement checksum calculation
        if len(data) % 2 == 1:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        # fold 32-bit to 16-bit
        s = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        chksum = ~s & 0xFFFF
        return chksum

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