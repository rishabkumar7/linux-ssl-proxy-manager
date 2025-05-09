#!/bin/bash

# Linux SSL Proxy Manager
# A script to automate setting up local SSL proxies on Linux

set -e

# Configuration
DOMAINS_DIR="$HOME/.local-ssl-proxy/domains"
CERTS_DIR="$HOME/.local-ssl-proxy/certs"
NGINX_CONFS_DIR="$HOME/.local-ssl-proxy/nginx"
SERVICES_DIR="$HOME/.local-ssl-proxy/services"
NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# Check for required tools
check_dependencies() {
  dependencies=("nginx" "openssl" "certutil" "systemctl")
  missing=()

  for cmd in "${dependencies[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
      missing+=("$cmd")
    fi
  done

  if [ ${#missing[@]} -ne 0 ]; then
    echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
    echo -e "${YELLOW}Installing required packages...${NC}"
    apt-get update
    apt-get install -y nginx openssl libnss3-tools
    if [ $? -ne 0 ]; then
      echo -e "${RED}Failed to install dependencies. Please install them manually.${NC}"
      exit 1
    fi
  fi
}

# Create necessary directories
create_directories() {
  mkdir -p "$DOMAINS_DIR" "$CERTS_DIR" "$NGINX_CONFS_DIR" "$SERVICES_DIR"
}

# Generate self-signed SSL certificate
generate_ssl_cert() {
  local domain="$1"
  local cert_dir="$CERTS_DIR/$domain"
  
  mkdir -p "$cert_dir"
  
  # Generate private key
  openssl genrsa -out "$cert_dir/privkey.pem" 2048
  
  # Create config file for OpenSSL
  cat > "$cert_dir/openssl.cnf" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = $domain

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[alt_names]
DNS.1 = $domain
DNS.2 = *.$domain
EOF

  # Generate certificate
  openssl req -new -x509 -key "$cert_dir/privkey.pem" -out "$cert_dir/fullchain.pem" \
    -days 365 -config "$cert_dir/openssl.cnf"
    
  echo -e "${GREEN}Certificate generated for $domain${NC}"
  
  # Trust certificate in browsers
  cert_db_dirs=()
  
  # Firefox
  for firefoxdir in ~/.mozilla/firefox/*.default ~/.mozilla/firefox/*.default-release; do
    if [ -d "$firefoxdir" ]; then
      cert_db_dirs+=("$firefoxdir")
    fi
  done
  
  # Chrome/Chromium
  for chromedir in ~/.pki/nssdb; do
    if [ -d "$chromedir" ]; then
      cert_db_dirs+=("$chromedir")
    fi
  done
  
  for certdb in "${cert_db_dirs[@]}"; do
    certutil -d "$certdb" -A -t "P,," -n "$domain" -i "$cert_dir/fullchain.pem"
  done
  
  # System-wide trust
  cp "$cert_dir/fullchain.pem" "/usr/local/share/ca-certificates/$domain.crt"
  update-ca-certificates
  
  echo -e "${GREEN}Certificate trusted in system and browsers${NC}"
}

# Create Nginx configuration
create_nginx_conf() {
  local domain="$1"
  local target="$2"
  local port="${3:-80}"
  
  # Create Nginx configuration file
  cat > "$NGINX_CONFS_DIR/$domain.conf" << EOF
server {
    listen 443 ssl;
    server_name $domain;

    ssl_certificate $CERTS_DIR/$domain/fullchain.pem;
    ssl_certificate_key $CERTS_DIR/$domain/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    
    location / {
        proxy_pass http://$target:$port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

  # Link to Nginx sites-available and sites-enabled
  ln -sf "$NGINX_CONFS_DIR/$domain.conf" "$NGINX_AVAILABLE/$domain.conf"
  ln -sf "$NGINX_AVAILABLE/$domain.conf" "$NGINX_ENABLED/$domain.conf"
  
  # Test Nginx configuration
  nginx -t
  
  # Reload Nginx
  systemctl reload nginx
  
  echo -e "${GREEN}Nginx configuration created and loaded for $domain${NC}"
}

# Add domain to /etc/hosts
update_hosts() {
  local domain="$1"
  local ip="${2:-127.0.0.1}"
  
  if ! grep -q "$domain" /etc/hosts; then
    echo "$ip $domain" >> /etc/hosts
    echo -e "${GREEN}Added $domain to /etc/hosts${NC}"
  else
    echo -e "${YELLOW}$domain already exists in /etc/hosts${NC}"
  fi
}

# Add a new domain
add_domain() {
  local domain="$1"
  local target="$2"
  local port="$3"
  
  if [ -z "$domain" ] || [ -z "$target" ]; then
    echo -e "${RED}Usage: $0 add <domain> <target> [port]${NC}"
    exit 1
  fi
  
  echo -e "${BLUE}Adding domain $domain pointing to $target:$port${NC}"
  
  # Save domain configuration
  echo "$target:$port" > "$DOMAINS_DIR/$domain"
  
  # Generate SSL certificate
  generate_ssl_cert "$domain"
  
  # Create Nginx configuration
  create_nginx_conf "$domain" "$target" "$port"
  
  # Update hosts file
  update_hosts "$domain"
  
  echo -e "${GREEN}Domain $domain successfully added!${NC}"
  echo -e "${YELLOW}You can now access your site at https://$domain${NC}"
}

# Remove a domain
remove_domain() {
  local domain="$1"
  
  if [ -z "$domain" ]; then
    echo -e "${RED}Usage: $0 remove <domain>${NC}"
    exit 1
  fi
  
  if [ ! -f "$DOMAINS_DIR/$domain" ]; then
    echo -e "${RED}Domain $domain not found${NC}"
    exit 1
  fi
  
  echo -e "${BLUE}Removing domain $domain${NC}"
  
  # Remove Nginx configuration
  rm -f "$NGINX_ENABLED/$domain.conf" "$NGINX_AVAILABLE/$domain.conf" "$NGINX_CONFS_DIR/$domain.conf"
  
  # Remove from hosts file
  sed -i "/\s$domain$/d" /etc/hosts
  
  # Remove certificate
  rm -rf "$CERTS_DIR/$domain"
  
  # Remove domain configuration
  rm -f "$DOMAINS_DIR/$domain"
  
  # Reload Nginx
  systemctl reload nginx
  
  echo -e "${GREEN}Domain $domain successfully removed!${NC}"
}

# List configured domains
list_domains() {
  echo -e "${BLUE}Configured domains:${NC}"
  
  if [ -z "$(ls -A "$DOMAINS_DIR" 2>/dev/null)" ]; then
    echo -e "${YELLOW}No domains configured${NC}"
    return
  fi
  
  printf "%-30s %-20s\n" "DOMAIN" "TARGET"
  echo "-------------------------------------------------"
  
  for domain_file in "$DOMAINS_DIR"/*; do
    domain=$(basename "$domain_file")
    target=$(cat "$domain_file")
    printf "%-30s %-20s\n" "$domain" "$target"
  done
}

# Create a GUI using zenity or yad if available
launch_gui() {
  if command -v yad &> /dev/null; then
    gui_tool="yad"
  elif command -v zenity &> /dev/null; then
    gui_tool="zenity"
  else
    echo -e "${YELLOW}GUI tools not found. Install 'yad' or 'zenity' for GUI support.${NC}"
    echo -e "${YELLOW}Falling back to CLI mode.${NC}"
    show_help
    return
  fi
  
  if [ "$gui_tool" = "yad" ]; then
    action=$(yad --title "Linux SSL Proxy Manager" --form \
      --field="Action:CB" "add!remove!list" \
      --button="Cancel:1" --button="Ok:0")
    ret=$?
    
    [ $ret -ne 0 ] && return
    
    action=$(echo "$action" | cut -d'|' -f1)
    
    case "$action" in
      "add")
        domain_info=$(yad --title "Add Domain" --form \
          --field="Domain:" "" \
          --field="Target:" "localhost" \
          --field="Port:" "3000" \
          --button="Cancel:1" --button="Add:0")
        ret=$?
        
        [ $ret -ne 0 ] && return
        
        domain=$(echo "$domain_info" | cut -d'|' -f1)
        target=$(echo "$domain_info" | cut -d'|' -f2)
        port=$(echo "$domain_info" | cut -d'|' -f3)
        
        add_domain "$domain" "$target" "$port"
        ;;
      "remove")
        domains=()
        for domain_file in "$DOMAINS_DIR"/*; do
          if [ -f "$domain_file" ]; then
            domains+=($(basename "$domain_file"))
          fi
        done
        
        if [ ${#domains[@]} -eq 0 ]; then
          yad --title "Remove Domain" --info --text="No domains configured"
          return
        fi
        
        domain_list=""
        for d in "${domains[@]}"; do
          domain_list+="$d!"
        done
        domain_list=${domain_list%!}
        
        domain=$(yad --title "Remove Domain" --form \
          --field="Domain:CB" "$domain_list" \
          --button="Cancel:1" --button="Remove:0")
        ret=$?
        
        [ $ret -ne 0 ] && return
        
        domain=$(echo "$domain" | cut -d'|' -f1)
        
        remove_domain "$domain"
        ;;
      "list")
        domain_list="DOMAIN\tTARGET\n"
        
        if [ -z "$(ls -A "$DOMAINS_DIR" 2>/dev/null)" ]; then
          yad --title "Domains" --info --text="No domains configured"
          return
        fi
        
        for domain_file in "$DOMAINS_DIR"/*; do
          domain=$(basename "$domain_file")
          target=$(cat "$domain_file")
          domain_list+="$domain\t$target\n"
        done
        
        yad --title "Configured Domains" --text-info --width=500 --height=300 \
          --wrap --no-edit --fore="#000000" --back="#ffffff" \
          --margins=10 --tabs=10 --editable=false \
          --text="$domain_list"
        ;;
    esac
  elif [ "$gui_tool" = "zenity" ]; then
    action=$(zenity --list --title "Linux SSL Proxy Manager" \
      --column="Action" "add" "remove" "list" \
      --width=300 --height=200)
    
    case "$action" in
      "add")
        domain=$(zenity --entry --title "Add Domain" --text="Domain:")
        [ -z "$domain" ] && return
        
        target=$(zenity --entry --title "Add Domain" --text="Target:" --entry-text="localhost")
        [ -z "$target" ] && return
        
        port=$(zenity --entry --title "Add Domain" --text="Port:" --entry-text="3000")
        [ -z "$port" ] && return
        
        add_domain "$domain" "$target" "$port"
        ;;
      "remove")
        domains=()
        for domain_file in "$DOMAINS_DIR"/*; do
          if [ -f "$domain_file" ]; then
            domains+=($(basename "$domain_file"))
          fi
        done
        
        if [ ${#domains[@]} -eq 0 ]; then
          zenity --info --title "Remove Domain" --text="No domains configured"
          return
        fi
        
        domain=$(zenity --list --title "Remove Domain" \
          --column="Domain" "${domains[@]}" \
          --width=300 --height=200)
        [ -z "$domain" ] && return
        
        remove_domain "$domain"
        ;;
      "list")
        domain_list="DOMAIN\tTARGET\n"
        
        if [ -z "$(ls -A "$DOMAINS_DIR" 2>/dev/null)" ]; then
          zenity --info --title "Domains" --text="No domains configured"
          return
        fi
        
        for domain_file in "$DOMAINS_DIR"/*; do
          domain=$(basename "$domain_file")
          target=$(cat "$domain_file")
          domain_list+="$domain\t$target\n"
        done
        
        echo -e "$domain_list" | zenity --text-info --title "Configured Domains" \
          --width=500 --height=300
        ;;
    esac
  fi
}

# Show help message
show_help() {
  echo -e "${BLUE}Linux SSL Proxy Manager${NC}"
  echo -e "A tool to easily set up SSL proxies for local development"
  echo
  echo -e "Usage:"
  echo -e "  $0 add <domain> <target> [port]   Add a new domain"
  echo -e "  $0 remove <domain>                Remove a domain"
  echo -e "  $0 list                           List all configured domains"
  echo -e "  $0 gui                            Launch graphical interface"
  echo -e "  $0 help                           Show this help message"
  echo
  echo -e "Examples:"
  echo -e "  $0 add my.custom.local localhost 3000"
  echo -e "  $0 remove my.custom.local"
}

# Main function
main() {
  check_dependencies
  create_directories
  
  local command="$1"
  shift
  
  case "$command" in
    add)
      add_domain "$@"
      ;;
    remove)
      remove_domain "$@"
      ;;
    list)
      list_domains
      ;;
    gui)
      launch_gui
      ;;
    help|--help|-h)
      show_help
      ;;
    *)
      if [ -z "$command" ]; then
        show_help
      else
        echo -e "${RED}Unknown command: $command${NC}"
        show_help
        exit 1
      fi
      ;;
  esac
}

# Run the script
main "$@"