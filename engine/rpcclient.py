import subprocess
import sys
import argparse

def enum_users_groups(target_ip, rpc_user="", rpc_pass=""):
    """
    Enumerates users and groups on a target system using rpcclient.

    Args:
        target_ip (str): IP address of the target system.
        rpc_user (str, optional): Username for rpcclient authentication. Defaults to "".
        rpc_pass (str, optional): Password for rpcclient authentication. Defaults to "".
    """

    if rpc_user and rpc_pass:
        auth_string = f'-U "{rpc_user}%{rpc_pass}"'
    else:
        auth_string = '-U "" -N'  # Null session

    try:
        # Enumerate domain users
        enum_users_command = f'rpcclient {auth_string} {target_ip} -c "enumdomusers"'
        enum_users_result = subprocess.run(enum_users_command, shell=True, capture_output=True, text=True, timeout=120)

        print("\n[+] Domain Users:")
        if enum_users_result.returncode == 0:
            print(enum_users_result.stdout)
        else:
            print(f"Error: {enum_users_result.stderr}")

        # Enumerate domain groups
        enum_groups_command = f'rpcclient {auth_string} {target_ip} -c "enumdomgroups"'
        enum_groups_result = subprocess.run(enum_groups_command, shell=True, capture_output=True, text=True, timeout=120)

        print("\n[+] Domain Groups:")
        if enum_groups_result.returncode == 0:
            print(enum_groups_result.stdout)
        else:
            print(f"Error: {enum_groups_result.stderr}")

    except subprocess.TimeoutExpired:
        print("[!] Timeout expired during rpcclient execution.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")


def main():
    parser = argparse.ArgumentParser(description="Enumerate users and groups on a Windows system using rpcclient.")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("-u", "--username", help="Username for rpcclient authentication (optional)")
    parser.add_argument("-p", "--password", help="Password for rpcclient authentication (optional)")

    args = parser.parse_args()

    enum_users_groups(args.target_ip, args.username if args.username else "", args.password if args.password else "")


if __name__ == "__main__":
    main()
