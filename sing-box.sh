#!/bin/bash
# bash <(curl -fsSL https://raw.githubusercontent.com/Arthurlu0421/demo/refs/heads/main/sing-box.sh)


# ==================================================
# 颜色与基础变量
# ==================================================
red="\033[31m\033[01m"
green="\033[32m\033[01m"
yellow="\033[33m\033[01m"
reset="\033[0m"

SBOX_DIR="/root/sing-box"
CONFIG_FILE="$SBOX_DIR/sb_config_server.json"
CLIENT_FILE="$SBOX_DIR/client.json"
BACKUP_DIR="$SBOX_DIR/backup"

info() { echo -e "${green}$*${reset}"; }
hint() { echo -e "${yellow}$*${reset}"; }
warning() { echo -e "${red}$*${reset}"; }
error() { warning "$*" && exit 1; }

# ==================================================
# 架构检测
# ==================================================
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "armv7" ;;
        i686|i386)     echo "386" ;;
        *)             error "不支持的架构: $arch" ;;
    esac
}

get_public_ip() {
    local ip=""
    for svc in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
        ip=$(curl -sS4 --connect-timeout 5 "$svc" 2>/dev/null) && break
    done
    [[ -z "$ip" ]] && error "无法获取公网 IP"
    echo "$ip"
}

# ==================================================
# 1. 环境初始化与端口检测 (整合自 New)
# ==================================================
generate_port() {
    local protocol="$1"
    local default_port="$2"
    while :; do
        read -p "请为 ${protocol} 输入监听端口(默认为 ${default_port}): " user_input
        local port=${user_input:-$default_port}
        if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
            warning "错误：端口号无效"
            continue
        fi
        if ss -tuln | grep -q ":${port}\b"; then
            warning "错误：端口 ${port} 已被占用，请更换"
            continue
        fi
        echo "$port"
        break
    done
}

prepare_env() {
    info "正在安装系统依赖..."
    apt-get update && apt-get install -y curl wget tar openssl socat jq || yum install -y curl wget tar openssl socat jq
    mkdir -p "$SBOX_DIR"
}

get_installed_version() {
    if [[ -x "$SBOX_DIR/sing-box" ]]; then
        "$SBOX_DIR/sing-box" version 2>/dev/null | head -1 | awk '{print $3}'
    else
        echo ""
    fi
}

install_binary() {
    local arch=$(detect_arch)
    local LAST_VER=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/v//')
    local installed_ver=$(get_installed_version)

    if [[ "$installed_ver" == "$LAST_VER" ]]; then
        info "sing-box 已是最新版本: v$LAST_VER"
        return 0
    fi

    info "正在安装 sing-box v$LAST_VER (架构: $arch)..."
    wget -qO- "https://github.com/SagerNet/sing-box/releases/download/v${LAST_VER}/sing-box-${LAST_VER}-linux-${arch}.tar.gz" | tar xz -C "$SBOX_DIR" --strip-components=1
    chmod +x "$SBOX_DIR/sing-box"
    info "sing-box v$LAST_VER 安装完成"
}

# ==================================================
# 2. 协议配置逻辑 (动态数组)
# ==================================================
select_and_configure() {
    echo -e "\n${green}请选择要安装的协议 (空格隔开，如: 1 2):${reset}"
    echo "1. Reality (VLESS)  - 推荐，抗检测能力强"
    echo "2. Hysteria2        - UDP协议，速度快"
    echo "3. ShadowTLS (V3)   - 伪装性好"
    echo "4. Anytls           - 新型TLS协议"
    read -p "选择: " choices

    SERVER_IP=$(get_public_ip)
    info "检测到服务器IP: $SERVER_IP"
    server_inbounds=()
    client_outbounds=()
    active_tags=()

    for choice in $choices; do
        case $choice in
            1)
                reality_port=$(generate_port "Reality" 10443)
                reality_uuid=$(cat /proc/sys/kernel/random/uuid)
                reality_server_name="www.microsoft.com"
                keys=$("$SBOX_DIR/sing-box" generate reality-keypair)
                private_key=$(echo "$keys" | grep -i "private" | awk '{print $NF}')
                public_key=$(echo "$keys" | grep -i "public" | awk '{print $NF}')
                short_id=$(openssl rand -hex 8)

                active_tags+=("🚀 Reality-VLESS")
                # 服务端
                server_inbounds+=("$(jq -nc \
                    --argjson port "$reality_port" \
                    --arg uuid "$reality_uuid" \
                    --arg sni "$reality_server_name" \
                    --arg pk "$private_key" \
                    --arg sid "$short_id" \
                    '{type:"vless",tag:"vless-in",listen:"::",listen_port:$port,sniff:true,sniff_override_destination:true,users:[{uuid:$uuid,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$sni,reality:{enabled:true,handshake:{server:$sni,server_port:443},private_key:$pk,short_id:[$sid]}}}')")
                # 客户端
                client_outbounds+=("$(jq -nc \
                    --arg ip "$SERVER_IP" \
                    --argjson port "$reality_port" \
                    --arg uuid "$reality_uuid" \
                    --arg sni "$reality_server_name" \
                    --arg pubk "$public_key" \
                    --arg sid "$short_id" \
                    '{tag:"🚀 Reality-VLESS",type:"vless",server:$ip,server_port:$port,uuid:$uuid,flow:"xtls-rprx-vision",packet_encoding:"xudp",tls:{enabled:true,server_name:$sni,utls:{enabled:true,fingerprint:"chrome"},reality:{enabled:true,public_key:$pubk,short_id:$sid}}}')")
                info "Reality 配置完成 (端口: $reality_port)"
                ;;
            2)
                hy2_port=$(generate_port "Hysteria2" 20443)
                hy2_password=$(openssl rand -base64 16)
                mkdir -p "$SBOX_DIR/hy2-cert"
                openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                    -keyout "$SBOX_DIR/hy2-cert/private.key" \
                    -out "$SBOX_DIR/hy2-cert/cert.pem" \
                    -days 3650 -subj "/CN=www.bing.com" 2>/dev/null

                active_tags+=("🚄 Hysteria2")
                # 服务端
                server_inbounds+=("$(jq -nc \
                    --argjson port "$hy2_port" \
                    --arg pwd "$hy2_password" \
                    --arg cert "$SBOX_DIR/hy2-cert/cert.pem" \
                    --arg key "$SBOX_DIR/hy2-cert/private.key" \
                    '{type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$port,sniff:true,sniff_override_destination:true,users:[{password:$pwd}],tls:{enabled:true,alpn:["h3"],certificate_path:$cert,key_path:$key}}')")
                # 客户端
                client_outbounds+=("$(jq -nc \
                    --arg ip "$SERVER_IP" \
                    --argjson port "$hy2_port" \
                    --arg pwd "$hy2_password" \
                    '{tag:"🚄 Hysteria2",type:"hysteria2",server:$ip,server_port:$port,password:$pwd,tls:{enabled:true,server_name:"www.bing.com",insecure:true,alpn:["h3"]}}')")
                info "Hysteria2 配置完成 (端口: $hy2_port)"
                ;;
            3)
                stls_port=$(generate_port "ShadowTLS" 30443)
                stls_password=$("$SBOX_DIR/sing-box" generate rand --base64 16 2>/dev/null || openssl rand -base64 16)
                ss_password=$("$SBOX_DIR/sing-box" generate rand --base64 16 2>/dev/null || openssl rand -base64 16)

                active_tags+=("🛡️ ShadowTLS")
                # 服务端
                server_inbounds+=("$(jq -nc \
                    --argjson port "$stls_port" \
                    --arg pwd "$stls_password" \
                    '{type:"shadowtls",tag:"shadowtls-in",listen:"::",listen_port:$port,detour:"shadowsocks-in",version:3,users:[{password:$pwd}],handshake:{server:"www.cloudflare.com",server_port:443},strict_mode:true}')")
                server_inbounds+=("$(jq -nc \
                    --arg pwd "$ss_password" \
                    '{type:"shadowsocks",tag:"shadowsocks-in",listen:"127.0.0.1",listen_port:0,method:"2022-blake3-aes-128-gcm",password:$pwd}')")
                # 客户端
                client_outbounds+=("$(jq -nc \
                    --arg ip "$SERVER_IP" \
                    --argjson port "$stls_port" \
                    --arg stls_pwd "$stls_password" \
                    --arg ss_pwd "$ss_password" \
                    '{tag:"🛡️ ShadowTLS",type:"shadowsocks",server:$ip,server_port:$port,method:"2022-blake3-aes-128-gcm",password:$ss_pwd,plugin:"shadow-tls",plugin_opts:("host=www.cloudflare.com;password="+$stls_pwd+";version=3")}')")
                info "ShadowTLS 配置完成 (端口: $stls_port)"
                ;;
            4)
                anytls_port=$(generate_port "Anytls" 40443)
                anytls_password=$(openssl rand -base64 16)

                active_tags+=("🔐 Anytls")
                # 服务端
                server_inbounds+=("$(jq -nc \
                    --argjson port "$anytls_port" \
                    --arg pwd "$anytls_password" \
                    '{type:"anytls",tag:"anytls-in",listen:"::",listen_port:$port,sniff:true,sniff_override_destination:true,users:[{password:$pwd}],padding_scheme:"random"}')")
                # 客户端
                client_outbounds+=("$(jq -nc \
                    --arg ip "$SERVER_IP" \
                    --argjson port "$anytls_port" \
                    --arg pwd "$anytls_password" \
                    '{tag:"🔐 Anytls",type:"anytls",server:$ip,server_port:$port,password:$pwd,padding_scheme:"random"}')")
                info "Anytls 配置完成 (端口: $anytls_port)"
                ;;
            *)
                warning "无效选项: $choice"
                ;;
        esac
    done

    [[ ${#active_tags[@]} -eq 0 ]] && error "未配置任何有效协议"
}

# ==================================================
# 3. 完整配置文件生成 (使用 jq 优化)
# ==================================================
write_all_configs() {
    # 3.1 写入服务端配置
    local inbounds_json
    inbounds_json=$(printf '%s\n' "${server_inbounds[@]}" | jq -s '.')

    jq -n \
        --argjson inbounds "$inbounds_json" \
        '{
            log: { level: "info", timestamp: true },
            inbounds: $inbounds,
            outbounds: [{ type: "direct", tag: "direct" }],
            route: { auto_detect_interface: true, final: "direct" }
        }' > "$CONFIG_FILE"

    info "服务端配置已写入: $CONFIG_FILE"

    # 3.2 写入客户端配置
    local outbounds_json tags_json
    outbounds_json=$(printf '%s\n' "${client_outbounds[@]}" | jq -s '.')
    tags_json=$(printf '%s\n' "${active_tags[@]}" | jq -R -s 'split("\n") | map(select(length > 0))')

    jq -n \
        --argjson proxies "$outbounds_json" \
        --argjson tags "$tags_json" \
        '{
            log: { level: "trace", timestamp: true },
            experimental: {
                cache_file: { enabled: true, path: "cache.db" },
                clash_api: {
                    external_controller: "0.0.0.0:9090",
                    external_ui: "ui",
                    external_ui_download_url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                    external_ui_download_detour: "🌏 全球直连",
                    secret: "luzhihua",
                    default_mode: "rule"
                }
            },
            dns: {
                servers: [
                    { type: "local", tag: "local-dns" },
                    { type: "https", tag: "ali-dns", server: "223.5.5.5" },
                    { type: "https", tag: "google-dns", server: "8.8.8.8", "detour": "🚀 节点选择" }
                ],
                rules: [
                    { domain_suffix: ["ksyuncdn.com", "ks-cdn.com"], server: "ali-dns" },
                    { query_type: ["HTTPS"], action: "reject" },
                    { domain_suffix: ["cc", "vip"], action: "reject" },
                    { domain: ["333bbb777bbb.com", "fans.91selfie.com"], domain_regex: ["(^|\\\\.)12img\\\\d{6}\\\\.com$"], domain_suffix: ["8rs8i.com", "ee555aa888.com", "neecee4005.top", "888qq999ee.com", "zz999ww666.com", "f6s3i7d2o5m0u8p1k.com", "zqbao.vip", "imgdd.cc", "dsj2025.co", "8egf73csh.com", "cloudfront.net", "vsamhos.com", "mitsmax.com", "ftzwarrant.com", "2324s01tupian.com"], action: "reject", method: "default" },
                    { rule_set: ["geosite-category-ads-all", "my-block"], action: "reject", method: "default" },
                    { domain_suffix: ["aswgroup.net", "aswchn.local", "feishu.cn", "feishucdn.com", "feishu-3rd-party-services.com", "larksuite.com", "byteimg.com", "bytedance.com", "volccdn.com", "toutiaoimg.com", "pstatp.com", "snssdk.com"], server: "local-dns" },
                    { rule_set: ["geosite-microsoft"], server: "ali-dns" },
                    { rule_set: ["geosite-cn", "LZTV", "my-direct"], server: "ali-dns" },
                    { rule_set: "geosite-geolocation-!cn", server: "google-dns" }
                ],
                final: "google-dns",
                strategy: "ipv4_only",
                independent_cache: true
            },
            inbounds: [
                {
                    type: "tun",
                    tag: "tun-in",
                    mtu: 9000,
                    address: "172.19.0.1/30",
                    auto_route: true,
                    strict_route: true,
                    route_exclude_address: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "172.100.0.0/24"],
                    stack: "gvisor"
                }
            ],
            outbounds: (
                [
                    { tag: "🚀 节点选择", type: "selector", outbounds: (["♻️ 自动选择", "🌏 全球直连"] + $tags) },
                    { tag: "👨‍💻 Github", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" },
                    { tag: "🪟 Microsoft", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🌏 全球直连" },
                    { tag: "🍏 Apple", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🌏 全球直连" },
                    { tag: "🔥 YouTube", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" },
                    { tag: "🎥 Netflix", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" },
                    { tag: "🤖 openAI", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" },
                    { tag: "🎦 self-Videos", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" },
                    { tag: "📺 LZTV", type: "selector", outbounds: ["🌏 全球直连"] + $tags },
                    { tag: "🐠 漏网之鱼", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" },
                    { tag: "♻️ 自动选择", type: "urltest", outbounds: $tags, url: "http://www.gstatic.com/generate_204", interval: "10m0s", tolerance: 50 },
                    { tag: "GLOBAL", type: "selector", outbounds: (["🚀 节点选择", "🌏 全球直连", "♻️ 自动选择"] + $tags), "default": "🚀 节点选择" }
                ] + $proxies + [
                    { tag: "🌏 全球直连", type: "direct" }
                ]
            ),
            route: {
                rules: [
                    { inbound: "tun-in", action: "sniff" },
                    { domain_suffix: ["feishu.cn", "feishucdn.com", "feishu-3rd-party-services.com", "larksuite.com", "byteimg.com", "bytedance.com", "volccdn.com", "toutiaoimg.com", "pstatp.com", "snssdk.com"], action: "route", outbound: "🌏 全球直连" },
                    { protocol: "quic", action: "reject" },
                    { type: "logical", mode: "or", rules: [{ protocol: "dns" }, { port: 53 }], action: "hijack-dns" },
                    { network: "udp", port: 853, action: "hijack-dns" },
                    { domain: ["333bbb777bbb.com", "fans.91selfie.com", "go.9splt.com"], domain_regex: ["(^|\\\\.)12img\\\\d{6}\\\\.com$"], domain_suffix: ["8rs8i.com", "ee555aa888.com", "neecee4005.top", "888qq999ee.com", "zz999ww666.com", "f6s3i7d2o5m0u8p1k.com", "zqbao.vip", "imgdd.cc", "dsj2025.co", "8egf73csh.com"], action: "reject" },
                    { rule_set: ["geosite-category-ads-all", "my-block"], action: "reject" },
                    { rule_set: "LZTV", outbound: "📺 LZTV" },
                    { rule_set: ["geosite-private", "geoip-private"], outbound: "🌏 全球直连" },
                    { rule_set: ["geoip-cn", "geosite-cn", "my-direct"], outbound: "🌏 全球直连" },
                    { rule_set: "geosite-github", outbound: "👨‍💻 Github" },
                    { rule_set: "geosite-microsoft", outbound: "🪟 Microsoft" },
                    { rule_set: ["geoip-apple", "geosite-apple"], outbound: "🍏 Apple" },
                    { rule_set: ["geosite-netflix", "geoip-netflix"], outbound: "🎥 Netflix" },
                    { rule_set: "geosite-youtube", outbound: "🔥 YouTube" },
                    { rule_set: "geosite-openAI", outbound: "🤖 openAI" },
                    { rule_set: "geosite-geolocation-!cn", outbound: "🚀 节点选择" },
                    { clash_mode: "direct", outbound: "🌏 全球直连" },
                    { clash_mode: "global", outbound: "GLOBAL" }
                ],
                rule_set: [
                    { type: "remote", tag: "geosite-microsoft", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/microsoft.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-apple", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/apple.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-github", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/github.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-geolocation-!cn", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/geolocation-!cn.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-cn", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-private", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/private.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geoip-apple", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geoip/apple.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geoip-cn", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geoip-private", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-category-ads-all", url: "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/category-ads-all.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-netflix", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geoip-netflix", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/netflix.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "my-block", url: "https://raw.githubusercontent.com/Arthurlu0421/demo/refs/heads/main/sing-box_my_block.json", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "my-direct", url: "https://raw.githubusercontent.com/Arthurlu0421/demo/refs/heads/main/sing-box_my_direct.json", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "LZTV", url: "https://raw.githubusercontent.com/Arthurlu0421/demo/refs/heads/main/lztv.json", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-youtube", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs", download_detour: "🚀 节点选择" },
                    { type: "remote", tag: "geosite-openAI", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.srs", download_detour: "🚀 节点选择" }
                ],
                final: "🐠 漏网之鱼",
                auto_detect_interface: true,
                default_domain_resolver: { server: "google-dns", strategy: "ipv4_only" }
            }
        }' > "$CLIENT_FILE"

    info "客户端配置已写入: $CLIENT_FILE"
}

# ==================================================
# 4. 服务配置与启动
# ==================================================
setup_service() {
    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box Service
After=network.target

[Service]
WorkingDirectory=$SBOX_DIR
ExecStart=$SBOX_DIR/sing-box run -c $CONFIG_FILE
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box --now
}

# ==================================================
# 主执行流
# ==================================================
prepare_env
install_binary
select_and_configure
write_all_configs

if "$SBOX_DIR/sing-box" check -c "$CONFIG_FILE"; then
    setup_service
    systemctl restart sing-box
    info "=================================================="
    info "安装成功！"
    hint "服务端配置: $CONFIG_FILE"
    hint "客户端配置: $CLIENT_FILE (请下载至客户端使用)"
    info "=================================================="
else
    error "配置校验失败，请检查端口是否占用或逻辑错误。"
fi
