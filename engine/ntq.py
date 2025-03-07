import socket
import struct
import time
import sys
import argparse

TIME1970 = 2208988800

def gettime_ntp(addr='pool.ntp.org'):
    """
    Gets the time from an NTP server.
    """
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = b'\x1b' + b'\0' * 47
        client.sendto(data, (addr, 123))
        client.settimeout(5)
        data, address = client.recvfrom(1024)

        if data:
            t = struct.unpack('!12I', data)[10]
            t -= TIME1970
            return time.ctime(t), t
        else:
            print("No data received from NTP server.")
            return None, None

    except socket.gaierror:
        print(f"Error: Invalid NTP server address: {addr}")
        return None, None
    except socket.timeout:
        print("Timeout while waiting for NTP server response.")
        return None, None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None
    finally:
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get time from an NTP server.")
    parser.add_argument("ip_address", nargs='?', default='', help="NTP server IP address. If not provided, will prompt.")

    args = parser.parse_args()

    if args.ip_address:
        ntp_server = args.ip_address
        print(f"Using NTP server from command line: {ntp_server}")
    else:
        ntp_server = input("Enter NTP server address (e.g., pool.ntp.org): ")
        if not ntp_server:
            print("No NTP server address provided.  Using default: pool.ntp.org")
            ntp_server = 'pool.ntp.org'  # Or exit, or use a default

    time_data, timestamp = gettime_ntp(ntp_server)

    if time_data:
        print(f"Time from NTP server: {time_data}")
    else:
        print("Failed to retrieve time from NTP server.")
