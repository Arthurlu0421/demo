#!/bin/bash
# bash <(curl -fsSL https://raw.githubusercontent.com/Arthurlu0421/demo/refs/heads/main/sing-box.sh)

# 颜色定义
red="\033[31m\033[01m"
green="\033[32m\033[01m"
yellow="\033[33m\033[01m"
reset="\033[0m"
bold="\e[1m"

# 基础目录
SBOX_DIR="/root/sing-box"
CONFIG_FILE="$SBOX_DIR/sb_config_server.json"
BACKUP_FILE="/root/sb_config_server.json.bak"

# 辅助函数
warning() { echo -e "${red}$*${reset}"; }
error() { warning "$*" && exit 1; }
info() { echo -e "${green}$*${reset}"; }
hint() { echo -e "${yellow}$*${reset}"; }

show_notice() {
    local message="$1"
    local terminal_width=$(tput cols)
    local line=$(printf "%*s" "$terminal_width" | tr ' ' '*')
    local padding=$(((terminal_width - ${#message}) / 2))
    local padded_message="$(printf "%*s%s" $padding '' "$message")"
    warning "${bold}${line}${reset}"
    echo ""
    warning "${bold}${padded_message}${reset}"
    echo ""
    warning "${bold}${line}${reset}"
}

install_pkgs() {
    local pkgs=("jq" "iptables" "curl" "openssl")
    for pkg in "${pkgs[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            hint "开始安装 $pkg..."
            if command -v apt &>/dev/null; then
                sudo apt update >/dev/null 2>&1 && sudo apt install -y "$pkg" >/dev/null 2>&1
            elif command -v yum &>/dev/null; then
                sudo yum install -y "$pkg"
            fi
        fi
    done
}

# --- 新增：备份检测逻辑 ---
check_backup() {
    if [ -f "$BACKUP_FILE" ]; then
        echo ""
        hint "检测到旧的备份文件: $BACKUP_FILE"
        read -p "是否直接读取此备份配置并跳过后续设置？(y/n, 默认n): " use_bak
        if [[ "$use_bak" == "y" || "$use_bak" == "Y" ]]; then
            mkdir -p "$SBOX_DIR"
            cp "$BACKUP_FILE" "$CONFIG_FILE"
            info "备份配置恢复成功。"
            return 0
        fi
    fi
    return 1
}

# --- 新增：协议选择逻辑 ---
select_protocols() {
    echo ""
    info "请选择需要安装的协议 (多个请用空格隔开，如: 1 2):"
    echo "1. Reality (VLESS)"
    echo "2. Hysteria2"
    echo "3. ShadowTLS"
    echo "4. Anytls"
    read -p "请输入选项 (1-4): " prot_choices

    install_reality=false
    install_hy2=false
    install_stls=false
    install_any=false

    for choice in $prot_choices; do
        case $choice in
            1) install_reality=true ;;
            2) install_hy2=true ;;
            3) install_stls=true ;;
            4) install_any=true ;;
        esac
    done

    # 兜底校验
    if [ "$install_reality" = false ] && [ "$install_hy2" = false ] && [ "$install_stls" = false ] && [ "$install_any" = false ]; then
        error "至少需要选择一个协议进行安装。"
    fi
}

# 端口生成函数 (复用原脚本)
generate_port() {
    local protocol="$1"
    local default_port="$2"
    while :; do
        read -p "请为 ${protocol} 输入监听端口(默认为 ${default_port}): " user_input
        local port=${user_input:-$default_port}
        if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)) || ss -tuln | grep -q ":${port}\b"; then
            warning "端口无效或已被占用，请重新输入。"
            continue
        fi
        echo "$port"
        return 0
    done
}

# IP/国旗获取 (复用原脚本)
prefix_tag_ip() {
    local server_ip
    server_ip=$(curl -s4m8 ip.sb -k 2>/dev/null) || server_ip=$(curl -s6m8 ip.sb -k 2>/dev/null)
    echo -n "节点-$server_ip"
}

# 安装二进制 (复用原脚本)
install_singbox() {
    arch=$(uname -m)
    case ${arch} in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
    latest_version=${latest_version_tag#v}
    package_name="sing-box-${latest_version}-linux-${arch}"
    url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
    curl -sLo "/root/${package_name}.tar.gz" "$url"
    tar -xzf "/root/${package_name}.tar.gz" -C /root
    mkdir -p "$SBOX_DIR"
    mv "/root/${package_name}/sing-box" "$SBOX_DIR/sing-box"
    rm -rf "/root/${package_name}.tar.gz" "/root/${package_name}"
    chmod +x "$SBOX_DIR/sing-box"
}

# ----------------- 主程序开始 -----------------
install_pkgs
clear
info "Reality Hysteria2 ShadowTLS Anytls 四合一定制脚本"

# 检查是否已安装
if [ -f "$CONFIG_FILE" ] && [ -f "$SBOX_DIR/sing-box" ]; then
    warning "Sing-box 已经安装，请先执行卸载或手动删除目录。"
    exit 0
fi

# 1. 尝试备份恢复
if ! check_backup; then
    # 2. 如果不恢复备份，则进行交互配置
    select_protocols
    install_singbox

    # --- 协议参数生成逻辑 ---
    if [ "$install_reality" = true ]; then
        warning "配置 Reality..."
        key_pair=$($SBOX_DIR/sing-box generate reality-keypair)
        private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
        public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
        reality_uuid=$($SBOX_DIR/sing-box generate uuid)
        short_id=$($SBOX_DIR/sing-box generate rand --hex 8)
        reality_port=$(generate_port "Reality" 10443)
        reality_server_name="itunes.apple.com"
    fi

    if [ "$install_hy2" = true ]; then
        warning "配置 Hysteria2..."
        hy2_password=$($SBOX_DIR/sing-box generate rand --hex 12)
        hy2_port=$(generate_port "Hysteria2" 18443)
        mkdir -p "$SBOX_DIR/hy2-cert"
        openssl ecparam -genkey -name prime256v1 -out "$SBOX_DIR/hy2-cert/private.key"
        openssl req -new -x509 -days 36500 -key "$SBOX_DIR/hy2-cert/private.key" -out "$SBOX_DIR/hy2-cert/cert.pem" -subj "/CN=bing.com"
    fi

    if [ "$install_stls" = true ]; then
        warning "配置 ShadowTLS..."
        shadowtls_password=$($SBOX_DIR/sing-box generate rand --base64 16)
        shadowtls_port=$(generate_port "ShadowTLS" 8443)
        shadowtls_handshake_server="captive.apple.com"
    fi

    if [ "$install_any" = true ]; then
        warning "配置 Anytls..."
        anytls_password=$($SBOX_DIR/sing-box generate rand --hex 16)
        anytls_port=$(generate_port "Anytls" 28443)
        mkdir -p "$SBOX_DIR/anytls-cert"
        openssl ecparam -genkey -name prime256v1 -out "$SBOX_DIR/anytls-cert/private.key"
        openssl req -new -x509 -days 36500 -key "$SBOX_DIR/anytls-cert/private.key" -out "$SBOX_DIR/anytls-cert/cert.pem" -subj "/CN=apple.com"
    fi

    # --- 核心：按需生成 JSON 配置 ---
    cat > "$CONFIG_FILE" <<EOF
{
    "log": { "disabled": false, "level": "trace", "timestamp": true },
    "dns": { "servers": [{ "type": "local", "tag": "local" }], "strategy": "ipv4_only" },
    "inbounds": [
EOF

    # 动态拼接 Inbounds 数组，处理逗号
    first=true

    # Reality Inbound
    if [ "$install_reality" = true ]; then
        $first || echo "," >> "$CONFIG_FILE"
        cat >> "$CONFIG_FILE" <<EOF
        {
            "type": "vless", "tag": "vless-in", "listen": "::", "listen_port": $reality_port,
            "users": [{ "uuid": "$reality_uuid", "flow": "xtls-rprx-vision" }],
            "tls": { "enabled": true, "server_name": "$reality_server_name", "reality": { "enabled": true, "handshake": { "server": "$reality_server_name", "server_port": 443 }, "private_key": "$private_key", "short_id": ["$short_id"] } }
        }
EOF
        first=false
    fi

    # Hysteria2 Inbound
    if [ "$install_hy2" = true ]; then
        $first || echo "," >> "$CONFIG_FILE"
        cat >> "$CONFIG_FILE" <<EOF
        {
            "type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": $hy2_port,
            "users": [{ "password": "$hy2_password" }],
            "tls": { "enabled": true, "alpn": ["h3"], "certificate_path": "$SBOX_DIR/hy2-cert/cert.pem", "key_path": "$SBOX_DIR/hy2-cert/private.key" }
        }
EOF
        first=false
    fi

    # ShadowTLS Inbound
    if [ "$install_stls" = true ]; then
        $first || echo "," >> "$CONFIG_FILE"
        cat >> "$CONFIG_FILE" <<EOF
        {
            "type": "shadowtls", "tag": "shadowtls-in", "listen": "::", "listen_port": $shadowtls_port, "detour": "ss-in", "version": 3,
            "users": [{ "password": "$shadowtls_password" }], "handshake": { "server": "$shadowtls_handshake_server", "server_port": 443 }, "strict_mode": true
        },
        {
            "type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "method": "2022-blake3-aes-128-gcm", "password": "$shadowtls_password"
        }
EOF
        first=false
    fi

    # Anytls Inbound
    if [ "$install_any" = true ]; then
        $first || echo "," >> "$CONFIG_FILE"
        cat >> "$CONFIG_FILE" <<EOF
        {
            "type": "anytls", "tag": "anytls-in", "listen": "::", "listen_port": $anytls_port,
            "users": [{ "name": "user", "password": "$anytls_password" }],
            "tls": { "enabled": true, "certificate_path": "$SBOX_DIR/anytls-cert/cert.pem", "key_path": "$SBOX_DIR/anytls-cert/private.key" }
        }
EOF
        first=false
    fi

    # 封底
    cat >> "$CONFIG_FILE" <<EOF
    ],
    "outbounds": [{ "type": "direct", "tag": "direct" }],
    "route": { "auto_detect_interface": true, "final": "direct" }
}
EOF
fi

# 3. 创建系统服务并启动
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=$SBOX_DIR
ExecStart=$SBOX_DIR/sing-box run -c $CONFIG_FILE
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

if $SBOX_DIR/sing-box check -c $CONFIG_FILE; then
    systemctl daemon-reload
    systemctl enable --now sing-box
    info "安装完成！服务已启动。"
    info "配置文件位置: $CONFIG_FILE"
else
    error "JSON 格式校验失败，请检查脚本输出。"
fi
