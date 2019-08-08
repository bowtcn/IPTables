#!/bin/sh

##/////// -----------------------------------------------------------------------------------------------------
##/////// ############################## 重要 - WARNING! #################################################
##/////// ######                                                                                         ######
##/////// ###### 如果你不使用这些定义，也可以在前面加上#，                                               ###### 
##/////// ###### 另外，不要忘记下面实际IPTables中的行，用＃阻止它们！                                    ######
##/////// ######                                                                                         ######
##/////// ############################## 重要 - WARNING! #################################################
##/////// -----------------------------------------------------------------------------------------------------


####################################################
############# 自定义的东西在这里   #################
####################################################


#### 默认SSH端口(也可以用于FTP)
SSH_PORT="21:23"

#### 你GameServer端口(这将照顾RCON块和无效的数据包。
GAMESERVERPORTS="27015:27016"

#### 您的家庭IP，这仅适用于通过HLSW远程RCON，因为您可以在服务器上使用! RCON命令作为管理员。(http://www.whatismyip.com/)
#### 记得向下滚动，如果不打算使用YOUR_HOME_IP，在使用它的行前面添加#。
YOUR_HOME_IP="xxx.xxx.xxx.xxx"

#### 你想允许无限制地访问服务器托管在本机上的所有其他计算机/用户。
#### 记住要进一步向下滚动，并删除在使用WHITELISTED_IPS如果你打算使用此行前的＃
# WHITELISTED_IPS="xxx.xxx.xxx.xxx"

#### 您想要保护的UDP端口，这里通常使用3306 (MySQL)和64738(Mumble)。
#### 添加GameServers,以防大量有效的数据包涌入(跳过了防御)
#### 若要添加端口范围，请使用 ":", Example; "27015:27022" 
#### 您还可以将端口范围和单个端口一起添加，例如; "27015:27022,80"
UDP_PORTS_PROTECTION="27015:27016"

#### 您想要保护的端口(如果您希望保护一些端口，请删除#，也请删除下面实际IPTables中的#。
#### 若要添加端口范围，请使用 ":", Example; "27015:27022" 
#### 您还可以将端口范围和单个端口一起添加，例如; "27015:27022,80"

########## 记住，如果要使用TCP_PORTS_PROTECTION，请进一步向下滚动并删除前面的#。
# TCP_PORTS_PROTECTION="64738"

##########################################################
############# 定制的东西在这里结束		    ##############
##########################################################

###################################################################################################################
# _|___|___|___|___|___|___|___|___|___|___|___|___|                                                             ##
# ___|___|___|___|___|___|___|___|___|___|___|___|__        IPTables: Linux's 的主防线				             ##
# _|___|___|___|___|___|___|___|___|___|___|___|___|        IPTables: Linux's 的方式对DoS的孩子说不		         ##
# ___|___|___|___|___|___|___|___|___|___|___|___|__                                                             ##    
# _|___|___|___|___|___|___|___|___|___|___|___|___|        Version 1.0.2 -                                      ##
# ___|___|___|___|___|___|___|___|___|___|___|___|__        IPTables Script created by Sir                       ##
# _|___|___|___|___|___|___|___|___|___|___|___|___|                                                             ##
# ___|___|___|___|___|___|___|___|___|___|___|___|__        Sources used and Studied;                            ##
# _|___|___|___|___|___|___|___|___|___|___|___|___|                                                             ##
# ___|___|___|___|___|___|___|___|___|___|___|___|__  http://ipset.netfilter.org/iptables.man.html               ##
# _|___|___|___|___|___|___|___|___|___|___|___|___|  https://forums.alliedmods.net/showthread.php?t=151551      ##
# ___|___|___|___|___|___|___|___|___|___|___|___|__  http://www.cyberciti.biz/tips/linux-iptables-examples.html ##
###################################################################################################################

## 先清理规则!
##--------------------
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
##--------------------

## 规则
##--------------------
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
##--------------------

## 创建过滤器
##---------------------
iptables -N UDPfilter
iptables -N TCPfilter
iptables -N LOGINVALID
iptables -N LOGFRAGMENTED
iptables -N LOGTCP
iptables -N LOGBANNEDIP
##---------------------

## 创建过滤规则
##---------------------
iptables -A UDPfilter -m state --state NEW -m hashlimit --hashlimit-upto 1/sec --hashlimit-burst 5 --hashlimit-mode srcip,dstport --hashlimit-name UDPDOSPROTECT --hashlimit-htable-expire 60000 --hashlimit-htable-max 999999999 -j ACCEPT
iptables -A TCPfilter -m state --state NEW -m hashlimit --hashlimit-upto 1/sec --hashlimit-burst 5 --hashlimit-mode srcip,dstport --hashlimit-name TCPDOSPROTECT --hashlimit-htable-expire 60000 --hashlimit-htable-max 999999999 -j ACCEPT
iptables -A LOGINVALID -m limit --limit 60/min -j LOG --log-prefix "Invalid Packets Dropped: " --log-level 4
iptables -A LOGFRAGMENTED -m limit --limit 60/min -j LOG --log-prefix "Frag Packets Dropped: " --log-level 4
iptables -A LOGTCP -m limit --limit 60/min -j LOG --log-prefix "Malformed/Spam TCP Dropped: " --log-level 4
iptables -A LOGBANNEDIP -m limit --limit 60/min -j LOG --log-prefix "Dropped Banned IP: " --log-level 4
iptables -A LOGINVALID -j DROP
iptables -A LOGBANNEDIP -j DROP
iptables -A LOGFRAGMENTED -j DROP
iptables -A LOGTCP -j DROP

#### 允许自身
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -s $YOUR_HOME_IP -j ACCEPT

#### 允许白名单的ip
# iptables -A INPUT -s $WHITELISTED_IPS -j ACCEPT

#### 阻止数据包范围从 0:28, 30:32, 46 and 2521:65535 （从未使用，因此无效数据包） - 这将捕获所有DoS尝试和无效数据包（弱）DDoS攻击。
iptables -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 0:28 -j LOGINVALID
iptables -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 30:32 -j LOGINVALID
iptables -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 46 -j LOGINVALID
iptables -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 60 -j LOGINVALID
iptables -A INPUT -p udp -m multiport --dports $GAMESERVERPORTS -m length --length 2521:65535 -j LOGINVALID

#### 阻止碎片数据包
#### 请记住，如果您的Linux服务器充当路由器，这可能会严重影响一些事情，我建议在这种情况下删除/注释掉它。
iptables -A INPUT -f -j LOGFRAGMENTED

#### 阻止ICMP / Ping
iptables -A INPUT -p icmp -j DROP

#### 接受已建立的连接
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#### 阻止格式错误/空TCP数据包，同时强制新连接成为SYN数据包
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j LOGTCP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOGTCP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOGTCP

#### 使用时限速和取消注释TCP。
iptables -A INPUT -p udp -m multiport --dports $UDP_PORTS_PROTECTION -j UDPfilter
# iptables -A INPUT -p tcp -m multiport --dports $TCP_PORTS_PROTECTION -j TCPfilter

#### 如果使用SSH & 家庭IP。
# iptables -A INPUT -p tcp --dport $SSH_PORT -s $YOUR_HOME_IP -j ACCEPT
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m hashlimit --hashlimit-upto 1/sec --hashlimit-burst 20 --hashlimit-mode srcip,dstport --hashlimit-name SSHPROTECT --hashlimit-htable-expire 60000 --hashlimit-htable-max 999999999 -j ACCEPT

## 放弃一切!
##--------------------
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
iptables -A OUTPUT -j ACCEPT
##--------------------

############ 额外的帮助高流量（DDOS） ##################
############### 确保在启动时执行此脚本! #########
#######################################################################

echo "20000" > /proc/sys/net/ipv4/tcp_max_syn_backlog
echo "1" > /proc/sys/net/ipv4/tcp_synack_retries
echo "30" > /proc/sys/net/ipv4/tcp_fin_timeout
echo "5" > /proc/sys/net/ipv4/tcp_keepalive_probes
echo "15" > /proc/sys/net/ipv4/tcp_keepalive_intvl
echo "20000" > /proc/sys/net/core/netdev_max_backlog
echo "20000" > /proc/sys/net/core/somaxconn
echo "99999999" > /proc/sys/net/nf_conntrack_max
