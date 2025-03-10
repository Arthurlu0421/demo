#!/bin/bash


red="\033[31m\033[01m"
green="\033[32m\033[01m"
yellow="\033[33m\033[01m"
reset="\033[0m"
bold="\e[1m"

warning() { echo -e "${red}$*${reset}"; }
error() { warning "$*" && exit 1; }
info() { echo -e "${green}$*${reset}"; }
hint() { echo -e "${yellow}$*${reset}"; }

show_notice() {
    local message="$1"
    local terminal_width=$(tput cols)
    local line=$(printf "%*s" "$terminal_width" | tr ' ' '*')
    local padding=$(( (terminal_width - ${#message}) / 2 ))
    local padded_message="$(printf "%*s%s" $padding '' "$message")"
    warning "${bold}${line}${reset}"
    echo ""
    warning "${bold}${padded_message}${reset}"
    echo ""
    warning "${bold}${line}${reset}"
}

print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo
}


show_status(){
    singbox_pid=$(pgrep sing-box)
    singbox_status=$(systemctl is-active sing-box)
    if [ "$singbox_status" == "active" ]; then
        cpu_usage=$(ps -p $singbox_pid -o %cpu | tail -n 1)
        memory_usage_mb=$(( $(ps -p "$singbox_pid" -o rss | tail -n 1) / 1024 ))

        p_latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')
        latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')

        latest_version=${latest_version_tag#v}  # Remove 'v' prefix from version number
        p_latest_version=${p_latest_version_tag#v}  # Remove 'v' prefix from version number

        iswarp=$(grep '^WARP_ENABLE=' /root/sing-box/config | cut -d'=' -f2)
        hy2hop=$(grep '^HY2_HOPPING=' /root/sing-box/config | cut -d'=' -f2)

        warning "SING-BOX服务状态信息:"
        hint "========================="
        info "状态: 运行中"
        info "CPU 占用: $cpu_usage%"
        info "内存 占用: ${memory_usage_mb}MB"
        info "singbox测试版最新版本: $p_latest_version"
        info "singbox正式版最新版本: $latest_version"
        info "singbox当前版本(输入4管理切换): $(/root/sing-box/sing-box version 2>/dev/null | awk '/version/{print $NF}')"
        info "warp流媒体解锁(输入6管理): $(if [ "$iswarp" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        info "hy2端口跳跃(输入7管理): $(if [ "$hy2hop" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        hint "========================="
    else
        warning "SING-BOX 未运行！"
    fi

}

install_pkgs() {
  # Install qrencode, jq, and iptables if not already installed
  local pkgs=("qrencode" "jq" "iptables")
  for pkg in "${pkgs[@]}"; do
    if command -v "$pkg" &> /dev/null; then
      hint "$pkg 已经安装"
    else
      hint "开始安装 $pkg..."
      if command -v apt &> /dev/null; then
        sudo apt update > /dev/null 2>&1 && sudo apt install -y "$pkg" > /dev/null 2>&1
      elif command -v yum &> /dev/null; then
        sudo yum install -y "$pkg"
      elif command -v dnf &> /dev/null; then
        sudo dnf install -y "$pkg"
      else
        error "Unable to install $pkg. Please install it manually and rerun the script."
      fi
      hint "$pkg 安装成功"
    fi
  done
}

install_shortcut() {
  cat > /root/sing-box/sb.sh << EOF
#!/usr/bin/env bash
bash <(curl -fsSL https://raw.githubusercontent.com/Arthurlu0421/demo/refs/heads/main/install.sh) \$1
EOF
  chmod +x /root/sing-box/sb.sh
  ln -sf /root/sing-box/sb.sh /usr/bin/sb
}

reload_singbox() {
    if /root/sing-box/sing-box check -c /root/sing-box/sb_config_server.json; then
        echo "检查配置文件成功，开始重启服务..."
        if systemctl reload sing-box; then
            echo "服务重启成功."
        else
            error "服务重启失败，请检查错误日志"
        fi
    else
        error "配置文件检查错误，请检查配置文件"
    fi
}


install_singbox(){
		echo "请选择需要安装的SING-BOX版本:"
		echo "1. 正式版"
		echo "2. 测试版"
		read -p "输入你的选项 (1-2, 默认: 1): " version_choice
		version_choice=${version_choice:-1}
		# Set the tag based on user choice
		if [ "$version_choice" -eq 2 ]; then
			echo "Installing Alpha version..."
			latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')
		else
			echo "Installing Stable version..."
			latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
		fi
		# No need to fetch the latest version tag again, it's already set based on user choice
		latest_version=${latest_version_tag#v}  # Remove 'v' prefix from version number
		echo "Latest version: $latest_version"
		# Detect server architecture
		arch=$(uname -m)
		echo "本机架构为: $arch"
    case ${arch} in
      x86_64) arch="amd64" ;;
      aarch64) arch="arm64" ;;
      armv7l) arch="armv7" ;;
    esac
    # latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | grep -Po '"tag_name": "\K.*?(?=")' | sort -V | tail -n 1)
    # latest_version=${latest_version_tag#v}
    echo "最新版本为: $latest_version"
    package_name="sing-box-${latest_version}-linux-${arch}"
    url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
    curl -sLo "/root/${package_name}.tar.gz" "$url"
    tar -xzf "/root/${package_name}.tar.gz" -C /root
    mv "/root/${package_name}/sing-box" /root/sing-box
    rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"
    chown root:root /root/sing-box/sing-box
    chmod +x /root/sing-box/sing-box
}

change_singbox(){
			echo "切换SING-BOX版本..."
			echo ""
			# Extract the current version
			current_version_tag=$(/root/sing-box/sing-box version | grep 'sing-box version' | awk '{print $3}')

			# Fetch the latest stable and alpha version tags
			latest_stable_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
			latest_alpha_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')

			# Determine current version type (stable or alpha)
      if [[ $current_version_tag == *"-alpha"* || $current_version_tag == *"-rc"* || $current_version_tag == *"-beta"* ]]; then
				echo "当前为测试版，准备切换为最新正式版..."
				echo ""
				new_version_tag=$latest_stable_version
			else
				echo "当前为正式版，准备切换为最新测试版..."
				echo ""
				new_version_tag=$latest_alpha_version
			fi

			# Stop the service before updating
			systemctl stop sing-box

			# Download and replace the binary
			arch=$(uname -m)
			case $arch in
				x86_64) arch="amd64" ;;
				aarch64) arch="arm64" ;;
				armv7l) arch="armv7" ;;
			esac

			package_name="sing-box-${new_version_tag#v}-linux-${arch}"
			url="https://github.com/SagerNet/sing-box/releases/download/${new_version_tag}/${package_name}.tar.gz"

			curl -sLo "/root/${package_name}.tar.gz" "$url"
			tar -xzf "/root/${package_name}.tar.gz" -C /root
			mv "/root/${package_name}/sing-box" /root/sing-box/sing-box

			# Cleanup the package
			rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"

			# Set the permissions
			chown root:root /root/sing-box/sing-box
			chmod +x /root/sing-box/sing-box

			# Restart the service with the new binary
			systemctl daemon-reload
			systemctl start sing-box

			echo "Version switched and service restarted with the new binary."
			echo ""
}

generate_port() {
   local protocol="$1"
    while :; do
        port=$((RANDOM % 10001 + 10000))
        read -p "请为 ${protocol} 输入监听端口(默认为随机生成): " user_input
        port=${user_input:-$port}
        ss -tuln | grep -q ":$port\b" || { echo "$port"; return $port; }
        echo "端口 $port 被占用，请输入其他端口"
    done
}

modify_port() {
    local current_port="$1"
    local protocol="$2"
    while :; do
        read -p "请输入需要修改的 ${protocol} 端口，回车不修改 (当前 ${protocol} 端口为: $current_port): " modified_port
        modified_port=${modified_port:-$current_port}
        if [ "$modified_port" -eq "$current_port" ] || ! ss -tuln | grep -q ":$modified_port\b"; then
            break
        else
            echo "端口 $modified_port 被占用，请输入其他端口"
        fi
    done
    echo "$modified_port"
}

# client configuration
show_client_configuration() {
  server_ip=$(grep -o "SERVER_IP='[^']*'" /root/sing-box/config | awk -F"'" '{print $2}')
  public_key=$(grep -o "PUBLIC_KEY='[^']*'" /root/sing-box/config | awk -F"'" '{print $2}')
  reality_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' /root/sing-box/sb_config_server.json)
  reality_uuid=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .users[0].uuid' /root/sing-box/sb_config_server.json)
  reality_server_name=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.server_name' /root/sing-box/sb_config_server.json)
  short_id=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.reality.short_id[0]' /root/sing-box/sb_config_server.json)
  reality_link="vless://$reality_uuid@$server_ip:$reality_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reality_server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#SING-BOX-REALITY"
  echo ""
  show_notice "VISION_REALITY 通用链接 二维码 通用参数" 
  echo ""
  info "通用链接如下"
  echo "" 
  echo "$reality_link"
  echo ""
  info "二维码如下"
  echo ""
  qrencode -t UTF8 $reality_link
  echo ""
  info "客户端通用参数如下"
  echo "------------------------------------"
  echo "服务器ip: $server_ip"
  echo "监听端口: $reality_port"
  echo "UUID: $reality_uuid"
  echo "域名SNI: $reality_server_name"
  echo "Public Key: $public_key"
  echo "Short ID: $short_id"
  echo "------------------------------------"

  # hy2
  hy2_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' /root/sing-box/sb_config_server.json)
  hy2_server_name=$(grep -o "hy2_server_name='[^']*'" /root/sing-box/config | awk -F"'" '{print $2}')
  hy2_password=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .users[0].password' /root/sing-box/sb_config_server.json)
  ishopping=$(grep '^HY2_HOPPING=' /root/sing-box/config | cut -d'=' -f2)
  if [ "$ishopping" = "FALSE" ]; then
      hy2_link="hysteria2://$hy2_password@$server_ip:$hy2_port?insecure=1&sni=$hy2_server_name#SING-BOX-HYSTERIA2"
  else
      hopping_range=$(iptables -t nat -L -n -v | grep "udp" | grep -oP 'dpts:\K\d+:\d+' || ip6tables -t nat -L -n -v | grep "udp" | grep -oP 'dpts:\K\d+:\d+')
      if [ -z "$hopping_range" ]; then
          warning "端口跳跃已开启却未找到端口范围。"
          hy2_link="hysteria2://$hy2_password@$server_ip:$hy2_port?insecure=1&sni=$hy2_server_name#SING-BOX-HYSTERIA2"
      else
          formatted_range=$(echo "$hopping_range" | sed 's/:/-/')
          hy2_link="hysteria2://$hy2_password@$server_ip:$hy2_port?insecure=1&sni=$hy2_server_name&mport=${hy2_port},${formatted_range}#SING-BOX-HYSTERIA2"
      fi
  fi
  echo ""
  echo "" 
  show_notice "Hysteria2通用链接 二维码 通用参数" 
  echo ""
  info "通用链接如下"
  echo "" 
  echo "$hy2_link"
  echo ""
  info "二维码如下"
  echo ""
  qrencode -t UTF8 $hy2_link  
  echo ""
  info "客户端通用参数如下"
  echo "------------------------------------"
  echo "服务器ip: $server_ip"
  echo "端口号: $hy2_port"
  if [ "$ishopping" = "FALSE" ]; then
    echo "端口跳跃未开启"
  else
    echo "跳跃端口为${formatted_range}"
  fi
  echo "密码password: $hy2_password"
  echo "域名SNI: $hy2_server_name"
  echo "跳过证书验证（允许不安全）: True"
  echo "------------------------------------"


  echo ""
  echo ""
  show_notice "sing-box客户端配置1.11.0及以上"
cat << EOF
{
    "log": {
        "disabled": false,
        "level": "info",
        "timestamp": true
    },
    "experimental": {
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
            "external_ui_download_detour": "🚀 节点选择",
            "external_ui": "ui",
            "secret": "",
            "default_mode": "rule"
        },
        "cache_file": {
            "enabled": true,
            "path": "cache.db",
            "store_fakeip": false
        }
    },
    "dns": {
        "servers": [
            {
                "tag": "dns_direct",
                "address": "tls://223.5.5.5",
                "address_strategy": "ipv4_only",
                "strategy": "ipv4_only",
                "detour": "🎯 全球直连"
            },
            {
                "tag": "dns_proxy",
                "address": "https://8.8.8.8/dns-query",
                "address_strategy": "ipv4_only",
                "strategy": "ipv4_only",
                "detour": "🚀 节点选择"
            }
        ],
        "rules": [
            {
                "rule_set": "geosite-category-ads-all",
                "action": "reject",
                "method": "drop"
            },
            {
                "rule_set": "geosite-cn",
                "action": "route",
                "server": "dns_direct"
            },
            {
                "clash_mode": "direct",
                "server": "dns_direct"
            },
            {
                "clash_mode": "global",
                "server": "dns_proxy"
            },
            {
                "rule_set": "geosite-geolocation-!cn",
                "server": "dns_proxy"
            }
        ],
        "final": "dns_proxy",
        "disable_cache": true,
        "strategy": "ipv4_only"
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "address": "172.19.0.1/30",
            "mtu": 9000,
            "auto_route": true,
            "strict_route": true,
            "stack": "system",
            "platform": {
                "http_proxy": {
                    "enabled": true,
                    "server": "127.0.0.1",
                    "server_port": 2080
                }
            }
        },
        {
            "type": "mixed",
            "listen": "127.0.0.1",
            "listen_port": 2080,
            "users": []
        }
    ],
    "outbounds": [
        {
            "tag": "🚀 节点选择",
            "type": "selector",
            "outbounds": [
                "♻️ 自动选择",
                "🎯 全球直连",
                "sing-box-reality",
                "sing-box-hysteria2"
            ]
        },
        {
            "tag": "👨‍💻 Github",
            "type": "selector",
            "outbounds": [
                "♻️ 自动选择",
                "🎯 全球直连",
                "sing-box-reality",
                "sing-box-hysteria2"
            ],
            "default": "🚀 节点选择"
        },
        {
            "tag": "🪟 Microsoft",
            "type": "selector",
            "outbounds": [
                "♻️ 自动选择",
                "🎯 全球直连",
                "sing-box-reality",
                "sing-box-hysteria2"
            ],
            "default": "🚀 节点选择"
        },
        {
            "tag": "🍏 Apple",
            "type": "selector",
            "outbounds": [
                "♻️ 自动选择",
                "🎯 全球直连",
                "sing-box-reality",
                "sing-box-hysteria2"
            ],
            "default": "🚀 节点选择"
        },
        {
            "tag": "🐠 漏网之鱼",
            "type": "selector",
            "outbounds": [
                "♻️ 自动选择",
                "🎯 全球直连",
                "sing-box-reality",
                "sing-box-hysteria2"
            ],
            "default": "🚀 节点选择"
        },
        {
            "type": "vless",
            "tag": "sing-box-reality",
            "uuid": "$reality_uuid",
            "flow": "xtls-rprx-vision",
            "packet_encoding": "xudp",
            "server": "$server_ip",
            "server_port": $reality_port,
            "tls": {
                "enabled": true,
                "server_name": "$reality_server_name",
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                },
                "reality": {
                    "enabled": true,
                    "public_key": "$public_key",
                    "short_id": "$short_id"
                }
            }
        },
        {
            "type": "hysteria2",
            "server": "$server_ip",
            "server_port": $hy2_port,
            "tag": "sing-box-hysteria2",
            "password": "$hy2_password",
            "tls": {
                "enabled": true,
                "server_name": "$hy2_server_name",
                "insecure": true,
                "alpn": [
                    "h3"
                ]
            }
        },
        {
            "tag": "♻️ 自动选择",
            "type": "urltest",
            "outbounds": [
                "sing-box-reality",
                "sing-box-hysteria2"
            ],
            "url": "http://www.gstatic.com/generate_204",
            "interval": "10m",
            "tolerance": 50
        },
        {
            "tag": "GLOBAL",
            "type": "selector",
            "outbounds": [
                "🚀 节点选择",
                "sing-box-reality",
                "sing-box-hysteria2",
                "♻️ 自动选择"
            ],
            "default": "🚀 节点选择"
        },
        {
            "tag": "🎯 全球直连",
            "type": "direct"
        }
    ],
    "route": {
        "auto_detect_interface": true,
        "final": "🐠 漏网之鱼",
        "rules": [
            {
                "inbound": "tun-in",
                "action": "sniff"
            },
            {
                "protocol": "dns",
                "action": "hijack-dns"
            },
            {
                "domain": [
                    "clash.razord.top",
                    "yacd.metacubex.one",
                    "yacd.haishan.me",
                    "d.metacubex.one"
                ],
                "outbound": "🎯 全球直连"
            },
            {
                "rule_set": "geosite-category-ads-all",
                "action": "reject"
            },
            {
                "rule_set": [
                    "geosite-private",
                    "geoip-private"
                ],
                "outbound": "🎯 全球直连"
            },
            {
                "rule_set": [
                    "geoip-cn",
                    "geosite-cn"
                ],
                "outbound": "🎯 全球直连"
            },
            {
                "rule_set": "geosite-github",
                "outbound": "👨‍💻 Github"
            },
            {
                "rule_set": "geosite-microsoft",
                "outbound": "🪟 Microsoft"
            },
            {
                "rule_set": [
                    "geoip-apple",
                    "geosite-apple"
                ],
                "outbound": "🍏 Apple"
            },
            {
                "rule_set": "geosite-geolocation-!cn",
                "outbound": "🚀 节点选择"
            },
            {
                "clash_mode": "direct",
                "outbound": "🎯 全球直连"
            },
            {
                "clash_mode": "global",
                "outbound": "GLOBAL"
            }
        ],
        "rule_set": [
            {
                "tag": "geosite-microsoft",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/microsoft.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geosite-apple",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/apple.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geosite-github",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/github.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/geolocation-!cn.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geosite-private",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/private.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geoip-apple",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geoip/apple.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geoip-private",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs",
                "download_detour": "🚀 节点选择"
            },
            {
                "tag": "geosite-category-ads-all",
                "type": "remote",
                "format": "binary",
                "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/category-ads-all.srs",
                "download_detour": "🚀 节点选择"
            }
        ]
    }
}
EOF

}

enable_bbr() {
    bash <(curl -L -s https://raw.githubusercontent.com/teddysun/across/master/bbr.sh)
    echo ""
}

modify_singbox() {
    echo ""
    warning "开始修改VISION_REALITY 端口号和域名"
    echo ""
    reality_current_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' /root/sing-box/sb_config_server.json)
    reality_port=$(modify_port "$reality_current_port" "VISION_REALITY")
    info "生成的端口号为: $reality_port"
    reality_current_server_name=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.server_name' /root/sing-box/sb_config_server.json)
    reality_server_name="$reality_current_server_name"
    while :; do
        read -p "请输入需要偷取证书的网站，必须支持 TLS 1.3 and HTTP/2 (默认: $reality_server_name): " input_server_name
        reality_server_name=${input_server_name:-$reality_server_name}
        if curl --tlsv1.3 --http2 -sI "https://$reality_server_name" | grep -q "HTTP/2"; then
            break
        else
            warning "域名 $reality_server_name 不支持 TLS 1.3 或 HTTP/2，请重新输入."
        fi
    done
    info "域名 $reality_server_name 符合标准"
    echo ""
    warning "开始修改hysteria2端口号"
    echo ""
    hy2_current_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' /root/sing-box/sb_config_server.json)
    hy2_port=$(modify_port "$hy2_current_port" "HYSTERIA2")
    info "生成的端口号为: $hy2_port"
    info "修改hysteria2应用证书路径"
    hy2_current_cert=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .tls.certificate_path' /root/sing-box/sb_config_server.json)
    hy2_current_key=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .tls.key_path' /root/sing-box/sb_config_server.json)
    hy2_current_domain=$(grep -o "hy2_server_name='[^']*'" /root/sing-box/config | awk -F"'" '{print $2}')
    read -p "请输入证书域名 (默认: $hy2_current_domain): " hy2_domain
    hy2_domain=${hy2_domain:-$hy2_current_domain}
    read -p "请输入证书cert路径 (默认: $hy2_current_cert): " hy2_cert
    hy2_cert=${hy2_cert:-$hy2_current_cert}
    read -p "请输入证书key路径 (默认: $hy2_current_key): " hy2_key
    hy2_key=${hy2_key:-$hy2_current_key}
    jq --arg reality_port "$reality_port" \
    --arg hy2_port "$hy2_port" \
    --arg reality_server_name "$reality_server_name" \
    --arg hy2_cert "$hy2_cert" \
    --arg hy2_key "$hy2_key" \
    '
    (.inbounds[] | select(.tag == "vless-in") | .listen_port) |= ($reality_port | tonumber) |
    (.inbounds[] | select(.tag == "hy2-in") | .listen_port) |= ($hy2_port | tonumber) |
    (.inbounds[] | select(.tag == "vless-in") | .tls.server_name) |= $reality_server_name |
    (.inbounds[] | select(.tag == "vless-in") | .tls.reality.handshake.server) |= $reality_server_name |
    (.inbounds[] | select(.tag == "hy2-in") | .tls.certificate_path) |= $hy2_cert |
    (.inbounds[] | select(.tag == "hy2-in") | .tls.key_path) |= $hy2_key
    ' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
    
    sed -i "s/hy2_server_name='.*'/hy2_server_name='$hy2_domain'/" /root/sing-box/config

    reload_singbox
}

uninstall_singbox() {
    warning "开始卸载..."
    disable_hy2hopping
    systemctl disable --now sing-box > /dev/null 2>&1
    rm -f /etc/systemd/system/sing-box.service
    rm -f /root/sing-box/sb_config_server.json /root/sing-box/sing-box /root/sing-box/mianyang.sh
    rm -f /usr/bin/mianyang /root/sing-box/self-cert/private.key /root/sing-box/self-cert/cert.pem /root/sing-box/config
    rm -rf /root/sing-box/self-cert/ /root/sing-box/
    warning "卸载完成"
}

process_warp(){
    while :; do
        iswarp=$(grep '^WARP_ENABLE=' /root/sing-box/config | cut -d'=' -f2)
        if [ "$iswarp" = "FALSE" ]; then
          warning "分流解锁功能未开启，是否开启（一路回车默认为: warp v6解锁openai和奈飞）"
          read -p "是否开启? (y/n 默认为y): " confirm
          confirm=${confirm:-"y"}
          if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            enable_warp
          else
            break
          fi
        else
            warp_option=$(awk -F= '/^WARP_OPTION/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' /root/sing-box/config)
            case $warp_option in
                0)
                    current_option="手动分流(使用geosite和domain分流)"
                    ;;
                1)
                    current_option="全局分流(接管所有流量)"
                    ;;
                *)
                    current_option="unknow!"
                    ;;
            esac
            warp_mode=$(awk -F= '/^WARP_MODE/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' /root/sing-box/config)
            case $warp_mode in
                0)
                    current_mode="Ipv6优先"
                    current_mode1="warp-IPv6-prefer-out"
                    ;;
                1)
                    current_mode="Ipv4优先"
                    current_mode1="warp-IPv4-prefer-out"
                    ;;
                2)
                    current_mode="Ipv6仅允许"
                    current_mode1="warp-IPv6-out"
                    ;;
                3)
                    current_mode="Ipv4仅允许"
                    current_mode1="warp-IPv4-out"
                    ;;
                4)
                    current_mode="任意门解锁"
                    current_mode1="doko"
                    ;;
                5)
                    current_mode="ss解锁"
                    current_mode1="ss-out"
                    ;;
                *)
                    current_option="unknow!"
                    ;;
            esac
            echo ""
            warning "warp分流已经开启"
            echo ""
            hint "当前模式为: $current_mode"
            hint "当前状态为: $current_option"
            echo ""
            info "请选择选项："
            echo ""
            info "1. 切换为手动分流(geosite和domain分流)"
            info "2. 切换为全局分流(接管所有流量)" 
            info "3. 设置手动分流规则(geosite和domain分流)"  
            info "4. 切换为分流策略"
            info "5. 删除解锁"
            info "0. 退出"
            echo ""
            read -p "请输入对应数字（0-5）: " warp_input
        case $warp_input in
          1)
            jq '.route.final = "direct"' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
            sed -i "s/WARP_OPTION=.*/WARP_OPTION=0/" /root/sing-box/config
            reload_singbox
          ;;
          2)
          if [ "$current_mode1" != "doko" ]; then
            jq --arg current_mode1 "$current_mode1" '.route.final = $current_mode1' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
            sed -i "s/WARP_OPTION=.*/WARP_OPTION=1/" /root/sing-box/config
            reload_singbox
          else
            warning "任意门解锁无法使用全局接管，请使用ss解锁策略"
          fi
            ;;
          4)
          while :; do
              warning "请选择需要切换的分流策略"
              echo ""
              hint "当前状态为: $current_option"
              echo ""
              info "请选择切换的选项："
              echo ""
              info "1. Ipv6优先(默认)"
              info "2. Ipv4优先"
              info "3. 仅允许Ipv6"
              info "4. 仅允许Ipv4"
              info "5. 任意门链式解锁"
              info "6. ss链式解锁"
              info "0. 退出"
              echo ""

              read -p "请输入对应数字（0-5）: " user_input
              user_input=${user_input:-1}
              case $user_input in
                  1)
                      warp_out="warp-IPv6-prefer-out"
                      sed -i "s/WARP_MODE=.*/WARP_MODE=0/" /root/sing-box/config
                      break
                      ;;
                  2)
                      warp_out="warp-IPv4-prefer-out"
                      sed -i "s/WARP_MODE=.*/WARP_MODE=1/" /root/sing-box/config
                      break
                      ;;
                  3)
                      warp_out="warp-IPv6-out"
                      sed -i "s/WARP_MODE=.*/WARP_MODE=2/" /root/sing-box/config
                      break
                      ;;
                  4)
                      warp_out="warp-IPv4-out"
                      sed -i "s/WARP_MODE=.*/WARP_MODE=3/" /root/sing-box/config
                      break
                      ;;
                  5)
                      read -p "请输入落地机vps ip: " ipaddress
                      read -p "请输入落地机vps 端口: " tport
                      jq --arg new_address "$ipaddress" --argjson new_port "$tport" '.outbounds |= map(if .tag == "doko" then .override_address = $new_address | .override_port = ($new_port | tonumber) else . end)' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                      warp_out="doko"
                      sed -i "s/WARP_MODE=.*/WARP_MODE=4/" /root/sing-box/config
                      break
                      ;;
                  6)
                      read -p "请输入落地机vps ip: " ssipaddress
                      read -p "请输入落地机vps 端口: " sstport
                      read -p "请输入落地机vps ss密码: " sspwd
                      jq --arg new_address "$ssipaddress" --arg sspwd "$sspwd" --argjson new_port "$sstport" '.outbounds |= map(if .tag == "ss-out" then .server = $new_address | .password = $sspwd | .server_port = ($new_port | tonumber) else . end)' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                      warp_out="ss-out"
                      sed -i "s/WARP_MODE=.*/WARP_MODE=5/" /root/sing-box/config
                      break
                      ;;
                  0)
                      # Exit the loop if option 0 is selected
                      echo "退出warp"
                      exit 0
                      ;;
                  *)
                      # Handle invalid input
                      echo "无效的输入，请重新输入"
                      ;;
              esac
          done
            jq --arg warp_out "$warp_out" '.route.rules[].outbound |= $warp_out' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
            if [ "$warp_option" -ne 0 ]; then
              jq --arg warp_out "$warp_out" '.route.final = $warp_out' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
            fi
            reload_singbox
            ;;
          3)
            info "请选择："
            echo ""
            info "1. 手动添加geosite分流（适配singbox1.11.0)"
            info "2. 手动添加域名关键字匹配分流"
            info "0. 退出"
            echo ""

            read -p "请输入对应数字（0-2）: " user_input
            case $user_input in
                1)
                    while :; do
                      echo ""
                      warning "geosite分流为: "
                      #域名关键字为
                      jq '.route.rules[] | select(.rule_set) | .rule_set' /root/sing-box/sb_config_server.json
                      info "请选择操作："
                      echo "1. 添加geosite"
                      echo "2. 删除geosite"
                      echo "0. 退出"
                      echo ""

                      read -p "请输入对应数字（0-2）: " user_input

                      case $user_input in
                          1)
                            #add domain
                            read -p "请输入要添加的域名关键字（若要添加geosite-openai，输入openai）: " new_keyword
                            url="https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/$new_keyword.srs"
                            formatted_keyword="geosite-$new_keyword"
                            # 检查是否存在相同的 geosite 关键字
                            if jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set | any(. == $formatted_keyword)' /root/sing-box/sb_config_server.json | grep -q "true"; then
                              echo "geosite已存在，不添加重复项: $formatted_keyword"
                            else
                              http_status=$(curl -s -o /dev/null -w "%{http_code}" "$url")

                              if [ "$http_status" -eq 200 ]; then
                                # 如果不存在，则添加
                                  new_rule='{
                                    "tag": "'"$formatted_keyword"'",
                                    "type": "remote",
                                    "format": "binary",
                                    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/'"$new_keyword"'.srs",
                                    "download_detour": "direct"
                                  }'

                                jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set += [$formatted_keyword]' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                                jq --argjson new_rule "$new_rule" '.route.rule_set += [$new_rule]' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json

                                echo "geosite已添加: $new_rule"
                              else
                                echo "geosite srs文件不存在，请重新输入..."
                              fi
                            fi
                            ;;
                          2)
                            #delete domain keywords
                            read -p "请输入要删除的域名关键字（若要删除geosite-openai，输入openai） " keyword_to_delete
                            formatted_keyword="geosite-$keyword_to_delete"
                            if jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set | any(. == $formatted_keyword)' /root/sing-box/sb_config_server.json | grep -q "true"; then
                              jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set -= [$formatted_keyword]' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                              #卸载ruleset
                              jq --arg formatted_keyword "$formatted_keyword" 'del(.route.rule_set[] | select(.tag == $formatted_keyword))' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                              echo "域名关键字已删除: $formatted_keyword"
                            else
                              echo "域名关键字不存在，不执行删除操作: $formatted_keyword"
                            fi
                              ;;
                          0)
                              echo "退出"
                              break
                              ;;
                          *)
                              echo "无效的输入，请重新输入"
                              ;;
                      esac
                  done
                    break
                    ;;
                2)
                    while :; do
                      echo ""
                      warning "域名关键字为: "
                      #域名关键字为
                      jq '.route.rules[] | select(.domain_keyword) | .domain_keyword' /root/sing-box/sb_config_server.json
                      info "请选择操作："
                      echo "1. 添加域名关键字"
                      echo "2. 删除域名关键字"
                      echo "0. 退出"
                      echo ""

                      read -p "请输入对应数字（0-2）: " user_input

                      case $user_input in
                          1)
                            #add domain keywords
                            read -p "请输入要添加的域名关键字: " new_keyword
                            if jq --arg new_keyword "$new_keyword" '.route.rules[1].domain_keyword | any(. == $new_keyword)' /root/sing-box/sb_config_server.json | grep -q "true"; then
                              echo "域名关键字已存在，不添加重复项: $new_keyword"
                            else
                              jq --arg new_keyword "$new_keyword" '.route.rules[1].domain_keyword += [$new_keyword]' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                              echo "域名关键字已添加: $new_keyword"
                            fi
                            ;;
                          2)
                            #delete domain keywords
                            read -p "请输入要删除的域名关键字: " keyword_to_delete
                            if jq --arg keyword_to_delete "$keyword_to_delete" '.route.rules[1].domain_keyword | any(. == $keyword_to_delete)' /root/sing-box/sb_config_server.json | grep -q "true"; then
                              jq --arg keyword_to_delete "$keyword_to_delete" '.route.rules[1].domain_keyword -= [$keyword_to_delete]' /root/sing-box/sb_config_server.json > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp /root/sing-box/sb_config_server.json
                              echo "域名关键字已删除: $keyword_to_delete"
                            else
                              echo "域名关键字不存在，不执行删除操作: $keyword_to_delete"
                            fi
                              ;;
                          0)
                              echo "退出"
                              break
                              ;;
                          *)
                              echo "无效的输入，请重新输入"
                              ;;
                      esac
                  done

                    break
                    ;;

                0)
                    # Exit the loop if option 0 is selected
                    echo "退出"
                    exit 0
                    ;;
                *)
                    # Handle invalid input
                    echo "无效的输入"
                    ;;
            esac
            reload_singbox
            break
            ;;
          5)
              disable_warp
              break
            ;;
          *)
              echo "退出"
              break
              ;;
        esac


        fi
        echo "配置文件更新成功"
    done
}
enable_warp(){
    #默认提供的warp节点
  while :; do
      warning "请选择是否需要注册warp"
      echo ""
      info "请选择选项："
      echo ""
      info "1. 使用绵羊提供的warp节点(默认)"
      info "2. 使用手动刷的warp节点"
      info "0. 退出"
      echo ""
      read -p "请输入对应数字（0-2）: " user_input
      user_input=${user_input:-1}
      case $user_input in
          1)
              v6="2606:4700:110:87ad:b400:91:eadb:887f"
              private_key="wIC19yRRSJkhVJcE09Qo9bE3P3PIwS3yyqyUnjwNO34="
              reserved="XiBe"
              break
              ;;
          2)
              warning "开始注册warp..."
              output=$(bash -c "$(curl -L warp-reg.vercel.app)")
              v6=$(echo "$output" | grep -oP '"v6": "\K[^"]+' | awk 'NR==2')
              private_key=$(echo "$output" | grep -oP '"private_key": "\K[^"]+')
              reserved=$(echo "$output" | grep -oP '"reserved_str": "\K[^"]+')
              break
              ;;
          0)
              # Exit the loop if option 0 is selected
              echo "退出"
              exit 0
              ;;
          *)
              # Handle invalid input
              echo "无效的输入，请重新输入"
              ;;
      esac
  done
      ipaddress="1.0.0.1"
      tport=53
      ssipaddress="1.0.0.1"
      sstport=53
      sspwd="8JCsPssfgS8tiRwiMlhARg=="
  while :; do
      warning "请选择需要设置的策略（默认为warp-v6优先）"
      echo ""
      info "请选择选项："
      echo ""
      info "1. Ipv6优先(默认)"
      info "2. Ipv4优先"
      info "3. 仅允许Ipv6"
      info "4. 仅允许Ipv4"
      info "5. 任意门链式解锁"
      info "6. ss链式解锁"
      info "0. 退出"
      echo ""
      read -p "请输入对应数字（0-6）: " user_input
      user_input=${user_input:-1}
      case $user_input in
          1)
              warp_out="warp-IPv6-prefer-out"
              sed -i "s/WARP_MODE=.*/WARP_MODE=0/" /root/sing-box/config
              break
              ;;
          2)
              warp_out="warp-IPv4-prefer-out"
              sed -i "s/WARP_MODE=.*/WARP_MODE=1/" /root/sing-box/config
              break
              ;;
          3)
              warp_out="warp-IPv6-out"
              sed -i "s/WARP_MODE=.*/WARP_MODE=2/" /root/sing-box/config
              break
              ;;
          4)
              warp_out="warp-IPv4-out"
              sed -i "s/WARP_MODE=.*/WARP_MODE=3/" /root/sing-box/config
              break
              ;;
          5)
              read -p "请输入落地机vps ip: " ssipaddress
              read -p "请输入落地机vps 端口: " sstport
              warp_out="doko"
              sed -i "s/WARP_MODE=.*/WARP_MODE=4/" /root/sing-box/config
              break
              ;;
          6)
              read -p "请输入落地机vps ip: " ssipaddress
              read -p "请输入落地机vps 端口: " sstport
              read -p "请输入落地机vps ss密码: " sspwd
              warp_out="ss-out"
              sed -i "s/WARP_MODE=.*/WARP_MODE=5/" /root/sing-box/config
              break
              ;;
          0)
              # Exit the loop if option 0 is selected
              echo "退出"
              exit 0
              ;;
          *)
              # Handle invalid input
              echo "无效的输入，请重新输入"
              ;;
      esac
  done

      jq --arg private_key "$private_key" --arg v6 "$v6" --arg reserved "$reserved" --arg warp_out "$warp_out" --arg ipaddress "$ipaddress" --arg tport "$tport" --arg ssipaddress "$ssipaddress" --arg sstport "$sstport" --arg sspwd "$sspwd" '
          .route = {
            "final": "direct",
            "rules": [
              {
                "rule_set": ["geosite-openai","geosite-netflix"],
                "outbound": $warp_out
              },
              {
                "domain_keyword": [
                  "ipaddress"
                ],
                "outbound": $warp_out
              }
            ],
            "rule_set": [
              { 
                "tag": "geosite-openai",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs",
                "download_detour": "direct"
              },
              {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs",
                "download_detour": "direct"
              }
            ]
          } | .outbounds += [
            {
              "type": "direct",
              "tag": "warp-IPv4-out",
              "detour": "wireguard-out",
              "domain_strategy": "ipv4_only"
            },
            {
              "type": "direct",
              "tag": "warp-IPv6-out",
              "detour": "wireguard-out",
              "domain_strategy": "ipv6_only"
            },
            {
              "type": "direct",
              "tag": "warp-IPv6-prefer-out",
              "detour": "wireguard-out",
              "domain_strategy": "prefer_ipv6"
            },
            {
              "type": "direct",
              "tag": "warp-IPv4-prefer-out",
              "detour": "wireguard-out",
              "domain_strategy": "prefer_ipv4"
            },
            {
              "type": "wireguard",
              "tag": "wireguard-out",
              "server": "162.159.192.1",
              "server_port": 2408,
              "local_address": [
                "172.16.0.2/32",
                $v6 + "/128"
              ],
              "private_key": $private_key,
              "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
              "reserved": $reserved,
              "mtu": 1280
            },
            {
              "type": "direct",
              "tag": "doko",
              "override_address": $ipaddress,
              "override_port": ($tport | tonumber),
              "proxy_protocol": 0
            },
            {
              "type": "shadowsocks",
              "tag": "ss-out",
              "server": $ssipaddress,
              "server_port": ($sstport | tonumber),
              "method": "2022-blake3-aes-128-gcm",
              "password": $sspwd
            }
          ]' "/root/sing-box/sb_config_server.json" > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp "/root/sing-box/sb_config_server.json"

      sed -i "s/WARP_ENABLE=FALSE/WARP_ENABLE=TRUE/" /root/sing-box/config
      sed -i "s/WARP_OPTION=.*/WARP_OPTION=0/" /root/sing-box/config
      reload_singbox
}

disable_warp(){
    jq 'del(.route) | del(.outbounds[] | select(.tag == "warp-IPv4-out" or .tag == "warp-IPv6-out" or .tag == "doko" or .tag == "ss-out" or .tag == "warp-IPv4-prefer-out" or .tag == "warp-IPv6-prefer-out" or .tag == "wireguard-out"))' "/root/sing-box/sb_config_server.json" > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp "/root/sing-box/sb_config_server.json"
    sed -i "s/WARP_ENABLE=TRUE/WARP_ENABLE=FALSE/" /root/sing-box/config
    reload_singbox
}

update_singbox(){
    info "更新singbox..."
    install_singbox
    # 检查配置
    if /root/sing-box/sing-box check -c /root/sing-box/sb_config_server.json; then
      echo "检查配置文件成功，重启服务..."
      systemctl restart sing-box
    else
      error "启动失败，请检查配置文件"
    fi
}

generate_random_number() {
    # Generates an 8-digit random number
    echo $((10000000 + RANDOM % 90000000))
}
process_doko() {
  while :; do
      echo "已配置的任意门转发规则如下:"
      jq '.inbounds[] | select(.tag | startswith("direct-in")) | "\(.tag): 本机监听端口 \(.listen_port), 转发至ip \(.override_address), 转发至端口 \(.override_port)"' /root/sing-box/sb_config_server.json
      echo ""
      echo "选择操作:"
      echo "1. 添加规则"
      echo "2. 删除规则"
      echo "0. 退出"
      read -p "请输入选择的操作数字（0-2）: " choice
      case $choice in
          1)
              fport=$(generate_port "本机任意门入站")
              echo "本机端口为: $fport"
              read -p "请输入转发至的vps ip: " ipaddress
              read -p "请输入转发至的vps端口: " tport

              # Generate an 8-digit random number as tag_suffix
              tag_suffix=$(generate_random_number)

              tag="direct-in${tag_suffix}"

              jq --arg ipaddress "$ipaddress" --arg fport "$fport" --arg tport "$tport" --arg tag "$tag" '
                  .inbounds += [
                      {
                          "type": "direct",
                          "tag": $tag,
                          "listen": "::",
                          "listen_port": ($fport | tonumber),
                          "override_address": $ipaddress,
                          "override_port": ($tport | tonumber)
                      }
                  ]' "/root/sing-box/sb_config_server.json" > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp "/root/sing-box/sb_config_server.json"
              echo "已添加任意门规则配置 ($tag)"
              reload_singbox
              ;;
          2)
              echo "请输入要删除的任意门规则标签 (例如：direct-in1): "
              read delete_tag
              jq 'del(.inbounds[] | select(.tag == $delete_tag))' --arg delete_tag "$delete_tag" "/root/sing-box/sb_config_server.json" > /root/sing-box/sb_config_server.temp && mv /root/sing-box/sb_config_server.temp "/root/sing-box/sb_config_server.json"
              echo "已删除任意门规则 ($delete_tag)"
              reload_singbox
              ;;
          0)
              echo "退出"
              ;;
          *)
              echo "无效的选择"
              ;;
      esac
    done
}
process_dokoko() {
    warning "任意门落地机设置，目前只支持解锁使用443端口的网站"
    #TODO 目前只支持点对点操作，一台解锁对一台待解锁（为了防止端口直接暴露被利用），可以尝试使用singbox的路由规则，筛选入站的流量再流出，文档https://sing-box.sagernet.org/zh/configuration/route/rule/
    config_file="/root/sing-box/sb_config_server.json"
    tag="direct-in"
    existing_port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .listen_port' "$config_file")
    existing_ip=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .listen' "$config_file")

    if [ -n "$existing_port" ]; then
        echo "已存在的监听为: $existing_ip : $existing_port "
        read -p "是否删除已存在的配置？ (y/n): " delete_option
        if [ "$delete_option" = "y" ]; then
            jq --arg tag "$tag" '.inbounds = (.inbounds | map(select(.tag != $tag)))' "$config_file" > "${config_file}.temp" && mv "${config_file}.temp" "$config_file"
            echo "已删除配置"
            systemctl restart sing-box
        else
            echo "未删除配置"
        fi
    else
        while true; do
            read -p "请输入解锁服务监听端口: " fport
            if [[ -n "$fport" && "$fport" =~ ^[0-9]+$ ]]; then
                break
            else
                warning "端口必须为非空数字，请重新输入."
            fi
        done
        while true; do
          read -p "请输入被解锁机vps ip: " fip
          ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
          if [[ $fip =~ $ip_regex ]]; then
              break
          else
              warning "输入的IP地址格式不合法"
          fi
        done
        jq --arg fport "$fport" --arg fip "$fip" '
            .inbounds += [
                {   
                    "sniff": true,
                    "sniff_override_destination": true,
                    "type": "direct",
                    "tag": "direct-in",
                    "listen": $fip,
                    "listen_port": ($fport | tonumber),
                    "override_port": 443
                }
            ]' "$config_file" > "${config_file}.temp" && mv "${config_file}.temp" "$config_file"
        echo "已添加任意门解锁机配置"
        reload_singbox
    fi
}

process_ssko() {
    warning "开始SS落地机设置"
    config_file="/root/sing-box/sb_config_server.json"
    tag="ss-in"
    existing_port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .listen_port' "$config_file")
    existing_pwd=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .password' "$config_file")
    server_ip=$(grep -o "SERVER_IP='[^']*'" /root/sing-box/config | awk -F"'" '{print $2}')

    if [ -n "$existing_port" ]; then
        info "已存在ss入站配置,监听端口号为: $existing_port"
        info "已存在ss入站配置,密码为: $existing_pwd"
        info "本机ip为: $server_ip"
        echo ""
        read -p "是否删除已存在的配置？ (y/n): " delete_option
        if [ "$delete_option" = "y" ]; then
            jq --arg tag "$tag" '.inbounds = (.inbounds | map(select(.tag != $tag)))' "$config_file" > "${config_file}.temp" && mv "${config_file}.temp" "$config_file"
            echo "已删除配置"
            reload_singbox
        else
            echo "未删除配置"
        fi
    else
        while true; do
            read -p "请输入解锁服务监听端口: " fport
            if [[ -n "$fport" && "$fport" =~ ^[0-9]+$ ]]; then
                break
            else
                warning "端口必须为非空数字，请重新输入."
            fi
        done
        sspwd=$(/root/sing-box/sing-box generate rand 16 --base64)
        info "监听端口号为: $fport"
        info "ss密码为：$sspwd"
        info "本机ip为: $server_ip"
        jq --arg sspwd "$sspwd" --arg fport "$fport" '
            .inbounds += [
                {   
                    "type": "shadowsocks",
                    "tag": "ss-in",
                    "listen": "::",
                    "listen_port": ($fport | tonumber),
                    "method": "2022-blake3-aes-128-gcm",
                    "password": $sspwd
                }
            ]' "$config_file" > "${config_file}.temp" && mv "${config_file}.temp" "$config_file"
        echo "已添加ss解锁机配置"
        reload_singbox
    fi
}

process_singbox() {
  while :; do
    echo ""
    echo ""
    info "请选择选项："
    echo ""
    info "1. 重启sing-box"
    info "2. 更新sing-box内核"
    info "3. 查看sing-box状态"
    info "4. 查看sing-box实时日志"
    info "5. 查看sing-box服务端配置"
    info "6. 切换SINGBOX内核版本"
    info "0. 退出"
    echo ""
    read -p "请输入对应数字（0-6）: " user_input
    echo ""
    case "$user_input" in
        1)
            warning "重启sing-box..."
            # 检查配置
            if /root/sing-box/sing-box check -c /root/sing-box/sb_config_server.json; then
                info "检查配置文件，启动服务..."
                systemctl restart sing-box
            fi
            info "重启完成"
            break
            ;;
        2)
            update_singbox
            break
            ;;
        3)
            warning "singbox基本信息如下(ctrl+c退出)"
            systemctl status sing-box
            break
            ;;
        4)
            warning "singbox日志如下(ctrl+c退出)："
            journalctl -u sing-box -o cat -f
            break
            ;;
        5)
            echo "singbox服务端如下："
            cat /root/sing-box/sb_config_server.json
            break
            ;;
        6)
            change_singbox
            break
            ;;
        0)
          echo "退出"
          break
          ;;
        *)
            echo "请输入正确选项: 0-6"
            ;;
    esac
  done
}

process_hy2hopping(){
        while :; do
          ishopping=$(grep '^HY2_HOPPING=' /root/sing-box/config | cut -d'=' -f2)
          if [ "$ishopping" = "FALSE" ]; then
              warning "开始设置端口跳跃范围..."
              enable_hy2hopping       
          else
              warning "端口跳跃已开启"
              echo ""
              info "请选择选项："
              echo ""
              info "1. 关闭端口跳跃"
              info "2. 重新设置"
              info "3. 查看规则"
              info "0. 退出"
              echo ""
              read -p "请输入对应数字（0-3）: " hopping_input
              echo ""
              case $hopping_input in
                1)
                  disable_hy2hopping
                  echo "端口跳跃规则已删除"
                  break
                  ;;
                2)
                  disable_hy2hopping
                  echo "端口跳跃规则已删除"
                  echo "开始重新设置端口跳跃"
                  enable_hy2hopping
                  break
                  ;;
                3)
                  # 查看NAT规则
                  iptables -t nat -L -n -v | grep "udp"
                  ip6tables -t nat -L -n -v | grep "udp"
                  break
                  ;;
                0)
                  echo "退出"
                  break
                  ;;
                *)
                  echo "无效的选项,请重新选择"
                  ;;
              esac
          fi
        done
}
# 开启hysteria2端口跳跃
enable_hy2hopping(){
    hint "开启端口跳跃..."
    warning "注意: 端口跳跃范围不要覆盖已经占用的端口，否则会错误！"
    hy2_current_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' /root/sing-box/sb_config_server.json)
    read -p "输入UDP端口范围的起始值(默认40000): " -r start_port
    start_port=${start_port:-40000}
    read -p "输入UDP端口范围的结束值(默认41000): " -r end_port
    end_port=${end_port:-41000}
    iptables -t nat -A PREROUTING -i eth0 -p udp --dport $start_port:$end_port -j DNAT --to-destination :$hy2_current_port
    ip6tables -t nat -A PREROUTING -i eth0 -p udp --dport $start_port:$end_port -j DNAT --to-destination :$hy2_current_port

    sed -i "s/HY2_HOPPING=FALSE/HY2_HOPPING=TRUE/" /root/sing-box/config
}

disable_hy2hopping(){
  echo "正在关闭端口跳跃..."
  iptables -t nat -F PREROUTING >/dev/null 2>&1
  ip6tables -t nat -F PREROUTING >/dev/null 2>&1
  sed -i "s/HY2_HOPPING=TRUE/HY2_HOPPING=FALSE/" /root/sing-box/config
  #TOREMOVE compatible with legacy users
  sed -i "s/HY2_HOPPING='TRUE'/HY2_HOPPING=FALSE/" /root/sing-box/config
  echo "关闭完成"
}

#--------------------------------
print_with_delay "Reality Hysteria2 二合一脚本 by 绵阿羊" 0.03
echo ""
echo ""
install_pkgs
# Check if reality.json, sing-box, and sing-box.service already exist
if [ -f "/root/sing-box/sb_config_server.json" ] && [ -f "/root/sing-box/config" ] && [ -f "/root/sing-box/mianyang.sh" ] && [ -f "/usr/bin/mianyang" ] && [ -f "/root/sing-box/sing-box" ] && [ -f "/etc/systemd/system/sing-box.service" ]; then
    echo ""
    warning "sing-box-reality-hysteria2已安装"
    show_status
    echo ""
    hint "=======常规配置========="
    warning "请选择选项:"
    echo ""
    info "1. 重新安装"
    info "2. 修改配置"
    info "3. 显示客户端配置"
    info "4. sing-box基础操作"
    info "5. 一键开启bbr"
    info "6. 流媒体解锁"
    info "7. hysteria2端口跳跃"
    info "8. 本机添加任意门中转规则（本机做中转机）"
    info "0. 卸载"
    echo ""
    hint "=======落地机解锁配置======"
    echo ""
    info "9.  落地机任意门解锁（本机做解锁机）"
    info "10. 落地机ss解锁（本机做解锁机）"
    echo ""
    hint "========================="
    echo ""
    read -p "请输入对应数字 (0-10): " choice

    case $choice in
      1)
          uninstall_singbox
        ;;
      2)
          modify_singbox
          show_client_configuration
          exit 0
        ;;
      3)  
          show_client_configuration
          exit 0
      ;;	
      4)  
          process_singbox
          exit 0
          ;;
      5)
          enable_bbr
          mianyang
          exit 0
          ;;
      6)
          process_warp
          exit 0
          ;;
      7)
          process_hy2hopping
          exit 0
          ;;
      8) 
          process_doko
          exit 0
          ;;
      9) 
          process_dokoko
          exit 0
          ;;
      10) 
          process_ssko
          exit 0
          ;;
      0)
          uninstall_singbox
	        exit 0
          ;;
      *)
          echo "选择错误，退出"
          exit 1
          ;;
	esac
	fi

mkdir -p "/root/sing-box/"

install_singbox
echo ""
echo ""

warning "开始配置VISION_REALITY..."
echo ""
key_pair=$(/root/sing-box/sing-box generate reality-keypair)
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
info "生成的公钥为:  $public_key"
info "生成的私钥为:  $private_key"
reality_uuid=$(/root/sing-box/sing-box generate uuid)
short_id=$(/root/sing-box/sing-box generate rand --hex 8)
info "生成的uuid为:  $reality_uuid"
info "生成的短id为:  $short_id"
echo ""
reality_port=$(generate_port "VISION_REALITY")
info "生成的端口号为: $reality_port"
reality_server_name="itunes.apple.com"
while :; do
    read -p "请输入需要偷取证书的网站，必须支持 TLS 1.3 and HTTP/2 (默认: $reality_server_name): " input_server_name
    reality_server_name=${input_server_name:-$reality_server_name}

    if curl --tlsv1.3 --http2 -sI "https://$reality_server_name" | grep -q "HTTP/2"; then
        break
    else
        echo "域名 $reality_server_name 不支持 TLS 1.3 或 HTTP/2，请重新输入."
    fi
done
info "域名 $reality_server_name 符合."
echo ""
echo ""
# hysteria2
warning "开始配置hysteria2..."
echo ""
hy2_password=$(/root/sing-box/sing-box generate rand --hex 12)
info "password: $hy2_password"
echo ""
hy2_port=$(generate_port "HYSTERIA2")
info "生成的端口号为: $hy2_port"
read -p "输入自签证书域名 (默认为: bing.com): " hy2_server_name
hy2_server_name=${hy2_server_name:-bing.com}
mkdir -p /root/sing-box/self-cert/ && openssl ecparam -genkey -name prime256v1 -out /root/sing-box/self-cert/private.key && openssl req -new -x509 -days 36500 -key /root/sing-box/self-cert/private.key -out /root/sing-box/self-cert/cert.pem -subj "/CN=${hy2_server_name}"
info "自签证书生成完成,保存于/root/sing-box/self-cert/"
echo ""
echo ""
#get ip
server_ip=$(curl -s4m8 ip.sb -k) || server_ip=$(curl -s6m8 ip.sb -k)

#generate config
cat > /root/sing-box/config <<EOF
# VPS ip
SERVER_IP='$server_ip'
# Reality
PUBLIC_KEY='$public_key'
# Hysteria2
hy2_server_name='$hy2_server_name'
HY2_HOPPING=FALSE
# Warp
WARP_ENABLE=FALSE
# 1 2 3 4
WARP_MODE=1
# 0 局部分流 1 全局分流
WARP_OPTION=0
EOF

#generate singbox server config
cat > /root/sing-box/sb_config_server.json << EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "sniff": true,
      "sniff_override_destination": true,
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $reality_port,
      "users": [
        {
          "uuid": "$reality_uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$reality_server_name",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$reality_server_name",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    },
    {
        "sniff": true,
        "sniff_override_destination": true,
        "type": "hysteria2",
        "tag": "hy2-in",
        "listen": "::",
        "listen_port": $hy2_port,
        "users": [
            {
                "password": "$hy2_password"
            }
        ],
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "/root/sing-box/self-cert/cert.pem",
            "key_path": "/root/sing-box/self-cert/private.key"
        }
    }
  ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ]
}
EOF

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/root/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/sing-box/sing-box run -c /root/sing-box/sb_config_server.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

if /root/sing-box/sing-box check -c /root/sing-box/sb_config_server.json; then
    hint "check config profile..."
    systemctl daemon-reload
    systemctl enable sing-box > /dev/null 2>&1
    systemctl start sing-box
    systemctl restart sing-box
    install_shortcut
    show_client_configuration
    warning "输入sb,即可打开菜单"
else
    error "配置文件检查失败，启动失败!"
fi
