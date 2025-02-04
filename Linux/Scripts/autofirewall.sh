#!/bin/bash
set -euo pipefail

# Configuration Variables
IPV4_DC_PORTS_TCP="53,88,135,389,445,464,636,3268,3269,49152:65535"
IPV4_DC_PORTS_UDP="53,88,123,389,464"
IPV6_DC_PORTS_TCP="53,88,389,443,636,3268,3269"
IPV6_DC_PORTS_UDP="53,88,123,389,464"
SSH_RATE_LIMIT="5/minute"
SYSLOG_SERVER=""
LOG_PREFIX="FIREWALL"

# Runtime Variables
declare -a TEAM_IPS=()
declare -a DC_IPS=()
HOSTNAME=""
IN_DOMAIN=0
PACKAGE_MANAGER=""
RULES_FILE="/root/firewall.rules"
USE_CRONJOB=0

# Initialize logging
setup_logging() {
    logger -t "$LOG_PREFIX" "Starting firewall configuration"
    
    if [ -n "$SYSLOG_SERVER" ]; then
        echo "*.* @${SYSLOG_SERVER}:514" >> /etc/rsyslog.conf
        systemctl restart rsyslog || service rsyslog restart
        logger -t "$LOG_PREFIX" "Syslog forwarding to $SYSLOG_SERVER configured"
    fi
}

# Input validation
validate_ip() {
    local ip=$1
    local version=$2
    
    if [[ $version == "4" ]]; then
        if ! [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            return 1
        fi
    elif [[ $version == "6" ]]; then
        if ! [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
            return 1
        fi
    fi
    return 0
}

# Package management
install_packages() {
    local packages=("$@")
    
    case $PACKAGE_MANAGER in
        "apk") apk add --no-cache "${packages[@]}" >/dev/null ;;
        "yum") yum install -y "${packages[@]}" >/dev/null ;;
        "dnf") dnf install -y "${packages[@]}" >/dev/null ;;
        "apt") apt-get install -y "${packages[@]}" >/dev/null ;;
        "zypper") zypper install -y "${packages[@]}" >/dev/null ;;
    esac
}

# Firewall persistence
setup_persistence() {
    local restore_script="/etc/iptables/restore-firewall.sh"
    
    # Create restore script
    cat << EOF > "$restore_script"
#!/bin/bash
iptables-restore < $RULES_FILE
ip6tables-restore < $RULES_FILE.v6
EOF
    
    chmod 0500 "$restore_script"
    
    # Systemd service
    if systemctl is-enabled --quiet firewalld 2>/dev/null; then
        systemctl stop firewalld
        systemctl mask firewalld
    fi

    if command -v systemctl >/dev/null; then
        cat << EOF > /etc/systemd/system/firewall-persistent.service
[Unit]
Description=Firewall Rule Persistence
After=network.target

[Service]
Type=oneshot
ExecStart=$restore_script

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable firewall-persistent
    else
        cat << EOF > /etc/init.d/firewall-persistent
#!/sbin/openrc-run
description="Firewall Rule Persistence"

depend() {
    need net
}

start() {
    $restore_script
}
EOF
        chmod +x /etc/init.d/firewall-persistent
        rc-update add firewall-persistent default
    fi
}

# Main firewall rules
configure_firewall() {
    # Flush existing rules
    iptables -F
    ip6tables -F

    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP

    # Common rules for IPv4/IPv6
    for cmd in iptables ip6tables; do
        # Connection state tracking
        $cmd -A INPUT -m conntrack --ctstate INVALID -j DROP
        $cmd -A OUTPUT -m conntrack --ctstate INVALID -j DROP
        
        # Localhost
        $cmd -A INPUT -i lo -j ACCEPT
        $cmd -A OUTPUT -o lo -j ACCEPT
        
        # ICMP (v4) or ICMPv6
        if [ "$cmd" = "iptables" ]; then
            $cmd -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
            $cmd -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
        else
            $cmd -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 1/second -j ACCEPT
            $cmd -A OUTPUT -p icmpv6 --icmpv6-type echo-reply -j ACCEPT
        fi
        
        # Established connections
        $cmd -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        $cmd -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    done

    # Team IP rules (SSH with rate limiting)
    for ip in "${TEAM_IPS[@]}"; do
        iptables -A INPUT -p tcp --dport 22 -s "$ip" -m recent --name SSH --set
        iptables -A INPUT -p tcp --dport 22 -s "$ip" -m recent --name SSH --rcheck --seconds 60 --hitcount $SSH_RATE_LIMIT -j DROP
        iptables -A INPUT -p tcp --dport 22 -s "$ip" -j ACCEPT
    done

    # Domain Controller rules
    if [ $IN_DOMAIN -eq 1 ]; then
        for ip in "${DC_IPS[@]}"; do
            # IPv4 rules
            iptables -A INPUT -p tcp -s "$ip" -m multiport --dports "$IPV4_DC_PORTS_TCP" -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$ip" -m multiport --dports "$IPV4_DC_PORTS_TCP" -j ACCEPT
            iptables -A INPUT -p udp -s "$ip" -m multiport --dports "$IPV4_DC_PORTS_UDP" -j ACCEPT
            iptables -A OUTPUT -p udp -d "$ip" -m multiport --dports "$IPV4_DC_PORTS_UDP" -j ACCEPT
            
            # IPv6 rules
            ip6tables -A INPUT -p tcp -s "$ip" -m multiport --dports "$IPV6_DC_PORTS_TCP" -j ACCEPT
            ip6tables -A OUTPUT -p tcp -d "$ip" -m multiport --dports "$IPV6_DC_PORTS_TCP" -j ACCEPT
            ip6tables -A INPUT -p udp -s "$ip" -m multiport --dports "$IPV6_DC_PORTS_UDP" -j ACCEPT
            ip6tables -A OUTPUT -p udp -d "$ip" -m multiport --dports "$IPV6_DC_PORTS_UDP" -j ACCEPT
        done
    fi

    # Logging
    iptables -A INPUT -j LOG --log-prefix "${LOG_PREFIX}_DROP_IN: " --log-level 6
    iptables -A OUTPUT -j LOG --log-prefix "${LOG_PREFIX}_DROP_OUT: " --log-level 6
    ip6tables -A INPUT -j LOG --log-prefix "${LOG_PREFIX}_DROP_IN6: " --log-level 6
    ip6tables -A OUTPUT -j LOG --log-prefix "${LOG_PREFIX}_DROP_OUT6: " --log-level 6

    # Save rules
    iptables-save > "$RULES_FILE"
    ip6tables-save > "${RULES_FILE}.v6"
}

# User prompts
get_hostname() {
    read -rp "Enter system hostname: " HOSTNAME
    RULES_FILE="/root/${HOSTNAME}.rules"
}

get_domain_status() {
    if command -v realm &>/dev/null && realm list | grep -q 'configured'; then
        IN_DOMAIN=1
    elif command -v adcli &>/dev/null; then
        IN_DOMAIN=1
    else
        IN_DOMAIN=0
    fi
}

get_ips() {
    # Domain Controllers
    if [ $IN_DOMAIN -eq 1 ]; then
        echo "Enter Domain Controller IPs (space separated):"
        read -ra DC_IPS
        for ip in "${DC_IPS[@]}"; do
            validate_ip "$ip" 4 || validate_ip "$ip" 6 || {
                echo "Invalid IP: $ip"
                exit 1
            }
        done
    fi

    # Team IPs
    echo "Enter Team IPs (space separated):"
    read -ra TEAM_IPS
    for ip in "${TEAM_IPS[@]}"; do
        validate_ip "$ip" 4 || validate_ip "$ip" 6 || {
            echo "Invalid IP: $ip"
            exit 1
        }
    done
}

# Main execution
main() {
    # Detect package manager
    declare -a pkg_managers=("apk" "dnf" "yum" "apt" "zypper")
    for pm in "${pkg_managers[@]}"; do
        if command -v "$pm" &>/dev/null; then
            PACKAGE_MANAGER="$pm"
            break
        fi
    done

    [ -z "$PACKAGE_MANAGER" ] && {
        echo "Unsupported package manager"
        exit 1
    }

    # Install dependencies
    install_packages iptables ip6tables rsyslog

    # User configuration
    get_hostname
    get_domain_status
    get_ips

    # System configuration
    setup_logging
    setup_persistence
    configure_firewall

    echo -e "\nConfiguration complete. Rules will persist across reboots."
    echo "Saved rules to: $RULES_FILE and ${RULES_FILE}.v6"
}

# Execute main function
main
