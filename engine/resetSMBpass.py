import subprocess
import sys
import argparse

def change_password(username, target_ip, rpc_user, rpc_pass, new_pass):
    """
    Attempts to reset the password for the specified user via rpcclient.
    Returns True if the password change appears to be successful, False otherwise.
    """
    # rpcclient command with appropriate shell quoting
    command = f'rpcclient -U "{rpc_user}%{rpc_pass}" {target_ip} -c "setuserinfo2 {username} 23 \'{new_pass}\' "'

    try:
        # Execute the command with subprocess.run (safer than os.popen)
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)

        # Debug: Print output and errors
        print(f"Command executed: {command}")
        print(f"Stdout:\n{result.stdout}")
        print(f"Stderr:\n{result.stderr}")

        # Analysis of the output
        if "NT_STATUS_OK" in result.stdout:
            print(f"\n{'='*50}")
            print(f"[+++++++++++++++++++++++++++++++++] Password for {username} changed successfully!")
            print(f"{'='*50}\n")
            return True
        elif "NT_STATUS_ACCESS_DENIED" in result.stderr:
            print(f"[!] Access denied for {username}. Check the credentials and permissions of the account {rpc_user}.")
            return False
        elif "NT_STATUS_NO_SUCH_USER" in result.stderr:
             print(f"[!] User {username} not found.")
             return False
        else:
            print(f"[!] Unexpected error during password change for {username}:\n{result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print(f"[!] Timeout expired while executing the command for {username}.")
        return False
    except Exception as e:
        print(f"[!] Generic error during command execution: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Reset user passwords on a Windows server using rpcclient.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-u", "--rpc_user", required=True, help="Username for rpcclient authentication")
    parser.add_argument("-p", "--rpc_pass", required=True, help="Password for rpcclient authentication")
    parser.add_argument("-n", "--new_pass", required=True, help="New password to set")
    parser.add_argument("-f", "--userfile", required=True, help="File containing a list of usernames (one per line)")

    args = parser.parse_args()

    try:
        with open(args.userfile, 'r') as lines:
            for myuser in lines:
                myuser = myuser.strip()  # Remove spaces and newline
                print(f"\n[*] Attempting password change for user: {myuser}")
                change_password(myuser, args.target, args.rpc_user, args.rpc_pass, args.new_pass)

    except FileNotFoundError:
        print(f"Error: The file {args.userfile} was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"A generic error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
