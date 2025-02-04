#!/bin/bash

# Created by: Juan Azcuna https://github.com/Dalosuuu
# Date: 2025-02-05

# Purpose: Check Linux services for potential security issues by analyzing:
# - Services running as root
# - Services with unusual file permissions
# - Services with binaries in non-standard locations
# - Services with missing binaries
# - Services with world-writable executable paths
# - Services that are listening on network ports

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize counters
total_services=0
root_services=0
nonstandard_locations=0
missing_binaries=0
reduce_privilege_candidates=0

# Function to check if path is standard
check_standard_path() {
    local path=$1
    [[ "$path" =~ ^(/usr/bin|/usr/sbin|/bin|/sbin) ]]
}

# Function to check file permissions
check_permissions() {
    local path=$1
    if [ -f "$path" ]; then
        # Check if world-writable
        if [ -w "$path" ] && [ "$(stat -c %A "$path" | cut -c9)" == "w" ]; then
            echo -e "${RED}WARNING: File is world-writable${NC}"
            return 1
        fi
        # Check if not owned by root
        if [ "$(stat -c %U "$path")" != "root" ]; then
            echo -e "${YELLOW}WARNING: File not owned by root${NC}"
            return 1
        fi
    fi
    return 0
}

# Function to find actual binary path of a service 
find_binary_path() {
    local cmd=$1
    # Remove any arguments from the command
    cmd=$(echo "$cmd" | awk '{print $1}')
    # Remove quotes if present
    cmd=${cmd//\"/}
    
    # Check if path exists directly
    if [ -f "$cmd" ]; then
        echo "$cmd"
        return 0
    fi
    
    # Try with which command
    local which_path=$(which "$cmd" 2>/dev/null)
    if [ -n "$which_path" ]; then
        echo "$which_path"
        return 0
    fi
    
    # Check common directories
    for dir in /bin /usr/bin /sbin /usr/sbin /usr/local/bin /usr/local/sbin /lib /usr/lib /usr/libexec; do
        if [ -f "$dir/$cmd" ]; then
            echo "$dir/$cmd"
            return 0
        fi
    done
    
    echo ""
    return 1
}

# Add severity levels to the warnings
check_service_security() {
    local service=$1
    local binary=$2
    local user=$3
    
    # Increment counters based on checks
    if [[ "$user" == "root" ]]; then
        ((root_services++))
        if [[ ! "$service" =~ ^(systemd|dbus|network|sshd) ]]; then
            ((reduce_privilege_candidates++))
        fi
    fi
    
    if ! check_standard_path "$binary"; then
        ((nonstandard_locations++))
    fi
    
    # Check for sensitive capabilities
    if command -v getcap >/dev/null 2>&1; then
        local caps=$(getcap "$binary" 2>/dev/null)
        if [ -n "$caps" ]; then
            echo -e "${YELLOW}INFO: Service binary has special capabilities: $caps${NC}"
        fi
    fi
    
    # Check if service is listening on network ports
    # This is to handle services that are listening on network ports 
    if command -v lsof >/dev/null 2>&1; then
        if pgrep -f "$binary" >/dev/null; then
            local ports=$(lsof -Pan -p $(pgrep -f "$binary") -i 2>/dev/null | grep LISTEN)
            if [ -n "$ports" ]; then
                echo -e "${YELLOW}INFO: Service is listening on network ports${NC}"
            fi
        fi
    fi
    
    # High severity issues
    if [[ -n "$binary" && -w "$binary" ]] && [[ "$(stat -c %A "$binary" | cut -c9)" == "w" ]]; then
        echo -e "${RED}CRITICAL: Binary is world-writable${NC}"
    fi
    
    # Medium severity issues
    if [[ "$user" == "root" && ! "$service" =~ ^(systemd|dbus|network|sshd) ]]; then
        echo -e "${YELLOW}WARNING: Service might not need root privileges${NC}"
    fi
    
    # Low severity issues
    if ! check_standard_path "$binary"; then
        echo -e "${YELLOW}INFO: Non-standard binary location (might be normal)${NC}"
    fi
}

echo "Checking system services for potential security issues..."
echo "------------------------------------------------------"

# Get list of unique services
services=$(systemctl list-units --type=service --all --plain --no-legend | cut -d' ' -f1 | sort -u)

# Main loop
for service in $services; do
    ((total_services++))
    
    echo -e "Analyzing service: ${GREEN}${service}${NC}"
    service_file=$(systemctl show -p FragmentPath "$service" | cut -d= -f2)
    echo "Service file: $service_file"
    
    # Get the command, properly handling multiple ExecStart entries
    # This is to handle services that have multiple commands to start
    command=$(systemctl show -p ExecStart "$service" | grep -oP 'path=\K[^ ]+' | head -n1)
    echo "Command: $command"
    
    # Check if binary exists
    if [ -n "$command" ] && [ -f "$command" ]; then
        echo "Executable found at: $command"
        echo "Checking permissions:"
        
        # Check if running as root
        if systemctl show "$service" | grep -q "User=$"; then
            ((root_services++))
            echo -e "${RED}WARNING: Service running as root${NC}"
            
            # Check for services that might not need root by checking agains known services
            # that are typically to run with root privileges as services that start with systemd,
            # dbus, network, sshd, or polkit
            if [[ ! "$service" =~ ^(systemd-|dbus|network|sshd|polkit) ]]; then
                ((reduce_privilege_candidates++))
                echo -e "${YELLOW}WARNING: Service might not need root privileges${NC}"
            fi
        fi
        
        # Checking for non-standard paths
        if ! check_standard_path "$command"; then
            ((nonstandard_locations++))
            echo -e "${YELLOW}INFO: Non-standard binary location (might be normal)${NC}"
        fi
    else
        ((missing_binaries++))
        echo -e "${RED}WARNING: Binary file not found${NC}"
    fi
    
    # Get and display service description from systemctl
    description=$(systemctl show -p Description "$service" | cut -d= -f2)
    echo "Description: $description"
    echo
    
    # Check service security
    check_service_security "$service" "$command" "$(systemctl show -p User "$service" | cut -d= -f2)"
done

# Display summary
echo -e "\nSummary:"
echo "----------------------------------------"
echo "Total services analyzed: $total_services"
echo "Services running as root: $root_services"
echo "Services with non-standard locations: $nonstandard_locations"
echo "Services with missing binaries: $missing_binaries"
echo "Potential privilege reduction candidates: $reduce_privilege_candidates"
echo -e "\nService check completed." 