import ipaddress as ipaddr
import ifaddr
import socket
from colorama import Fore, Back, init


class SocketValidator:
    def __init__(self, ip: str):
        if not ip:
            print(Fore.RED + "Invalid Ip Given" + Fore.WHITE)
            raise TypeError("Invalid IP Given failed to validate the ip None type")
        if not isinstance(ip, str):
            print(Fore.RED + "Invalid Ip Given a string instance is required" + Fore.WHITE)
            raise TypeError("Invalid IP Given failed to valid string type given")
        self.__ip = ip
        if not self.__Validate_ip():
            print(Fore.RED + "Something is wrong with the given ip" + Fore.WHITE)
            raise TypeError("Given ip value is invalid")
        if not self.__Check_if_ip_belongs_to_interface():
            print(Fore.RED + "This given ip doesn't belong to any of the given interfaces" + Fore.WHITE)
            raise TypeError("Given ip doesn't belong to any ip address")

    def __ValidatePort(self, port) -> bool:                     # FIX: return type bool, not False
        if not port:
            print(Fore.RED + "Failed to set the port , type None" + Fore.WHITE)
            return False
        if not isinstance(port, int):
            print(Fore.RED + "Failed to set the port , type of port needs to be white" + Fore.WHITE)
            return False
        if not (0 < port <= 65535):                            # FIX: proper range check (was precedence-broken)
            print(Fore.RED + "Failed to set the port, needs to be within (0,65535) range" + Fore.WHITE)
            return False
        return True

    @staticmethod                                              # FIX: was missing self / staticmethod
    def closeConnection(sock: socket.socket) -> None:
        if sock:
            print(Fore.CYAN + "Closing the given socket" + Fore.WHITE)
            sock.close()
        else:                                                  # FIX: only say "already closed" when it is
            print(Fore.GREEN + "Socket already closed" + Fore.WHITE)

    def establish_tcp_connection(self, connection_port) -> socket.socket:
        if not self.__ValidatePort(connection_port):
            print(Fore.RED + "Given Port is invalid" + Fore.WHITE)
            return None                                        # FIX: bail out on invalid port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # FIX: indentation
        if not sock.connect_ex((self.__ip, connection_port)) == 0:
            print(Fore.RED + "Failed to establish socket connection" + Fore.WHITE)
            sock.close()                                       # FIX: don't leak the socket on failure
            return None
        print(Fore.CYAN + "Connection to TCP Server has been established" + Fore.WHITE)
        return sock                                            # FIX: return the socket, not True

    def test_connection_using_a_socket(self, connection_port, grab_banner=False) -> tuple:
        try:
            response = None
            connection_status = False
            if not self.__ValidatePort(connection_port):
                print(Fore.RED + "Invalid Port To Connect To" + Fore.WHITE)
                return connection_status, response             # FIX: return tuple to match caller
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                if not sock.connect_ex((self.__ip, connection_port)) == 0:
                    print(Fore.RED + "Connection to the socket Failed" + Fore.WHITE)
                else:
                    print(Fore.GREEN + "Connection has been made succesfully" + Fore.WHITE)
                    connection_status = True
                    if grab_banner:
                        print(Fore.CYAN + "Grabbing Banner" + Fore.WHITE)   # FIX: was RED
                        try:                                   # FIX: don't let a slow/quiet banner
                            response = sock.recv(1024)         #      crash the whole call
                        except socket.timeout:
                            print(Fore.RED + "Banner grab timed out" + Fore.WHITE)
            return connection_status, response
        except Exception:
            print(Fore.RED + "Failed to establish the connection" + Fore.WHITE)  # FIX: log before re-raise
            raise                                              # FIX: bare raise preserves traceback

    def return_information_about_ip(self):
        ip_object = ipaddr.ip_address(self.__ip)
        return {
            "ip_addr": self.__ip,
        }

    def __Validate_ip(self) -> bool:
        try:
            print(Fore.CYAN + "Checking if the ip is valid" + Fore.WHITE)   # FIX: was "email"
            ipaddr.ip_address(self.__ip)                       # FIX: no dead assignment
            return True
        except Exception as e:
            print(Fore.RED + "Something is wrong with the given ip: {}".format(e) + Fore.WHITE)
            return False


    def __Check_if_ip_belongs_to_interface(self) -> bool:
        print(Fore.CYAN + "Checking the ip addr belongs to any of the given address" + Fore.WHITE)
        adapters = ifaddr.get_adapters()
        adap_found = False
        list_of_adaps = list(ipaddr.ip_network("192.168.56.0/24",strict=True).hosts())
        if ipaddr.ip_address(self.__ip) in list_of_adaps:
            print(Fore.CYAN + "This Given ip address belongs to host only network" + Fore.WHITE)
            return list_of_adaps
        for adapter in adapters:
            print("IPs of network adapter " + adapter.nice_name)
            for ip in adapter.ips:
                if self.__ip == ip.ip:
                    print(Fore.CYAN + "Given IP is found in interface : {}".format(adapter.nice_name))
                    adap_found = True
        return adap_found


if __name__ == "__main__":
    test = SocketValidator("127.0.0.1")
    print(test.test_connection_using_a_socket(22, True))
