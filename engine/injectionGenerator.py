import sys
import os

# Function to generate manipulated commands
def generate_manipulated_commands(base_command, prefixes, suffixes):
    #command_in_parentheses = f"$({base_command})"
    command_variants = [base_command]
    
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
prefixes = ["; ", "%00; ", "%0A"]
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
output_file = 'out-injection-list.txt'

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

# Append the new BASE64 section to the file
with open(output_file, 'a') as f:
    f.write("\n".join(base64_section) + "\n")

print("Command list generated successfully. Check 'out-injection-list.txt'.")
