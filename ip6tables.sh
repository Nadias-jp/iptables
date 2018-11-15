#!/bin/bash

###########################################################
# このスクリプトの特徴
#
# 受信・通過については基本的に破棄し、ホワイトリストで許可するものを指定する。
# 送信については基本的に許可する。ただし、サーバが踏み台になり外部のサーバに迷惑をかける可能性があるので、
# 心配な場合は、送信も受信同様に基本破棄・ホワイトリストで許可するように書き換えると良い。
###########################################################

###########################################################
# 用語の統一
# わかりやすさのためルールとコメントの用語を以下に統一する
# ACCEPT : 許可
# DROP   : 破棄
# REJECT : 拒否
###########################################################

###########################################################
# チートシート
#
# -A, --append       指定チェインに1つ以上の新しいルールを追加
# -D, --delete       指定チェインから1つ以上のルールを削除
# -P, --policy       指定チェインのポリシーを指定したターゲットに設定
# -N, --new-chain    新しいユーザー定義チェインを作成
# -X, --delete-chain 指定ユーザー定義チェインを削除
# -F                 テーブル初期化
#
# -p, --protocol      プロコトル         プロトコル(tcp、udp、icmp、all)を指定
# -s, --source        IPアドレス[/mask]  送信元のアドレス。IPアドレスorホスト名を記述
# -d, --destination   IPアドレス[/mask]  送信先のアドレス。IPアドレスorホスト名を記述
# -i, --in-interface  デバイス           パケットが入ってくるインターフェイスを指定
# -o, --out-interface デバイス           パケットが出ていくインターフェイスを指定
# -j, --jump          ターゲット         条件に合ったときのアクションを指定
# -t, --table         テーブル           テーブルを指定
# -m state --state    状態              パケットの状態を条件として指定
#                                       stateは、 NEW、ESTABLISHED、RELATED、INVALIDが指定できる
# !                   条件を反転（～以外となる）
###########################################################

# パス
PATH=/sbin:/usr/sbin:/bin:/usr/bin

###########################################################
# IPの定義
# 必要に応じて定義する。定義しなくても動作する。
###########################################################

# 内部ネットワークとして許可する範囲
# LOCAL_NET="xxxx:xxxx:xxxx:xxxx/xx"

# 内部ネットワークとして一部制限付きで許可する範囲
# LIMITED_LOCAL_NET="xxxx:xxxx:xxxx:xxxx/xx"

# ZabbixサーバーIP
# ZABBIX_IP="xxxx:xxxx:xxxx:xxxx"

# 全てのIPを表す設定を定義
# ANY="::/0"

# 信頼可能ホスト(配列)
# ALLOW_HOSTS=(
# 	"xxxx:xxxx:xxxx:xxxx"
# 	"xxxx:xxxx:xxxx:xxxx"
# 	"xxxx:xxxx:xxxx:xxxx"
# )

# 無条件破棄するリスト(配列)
# DENY_HOSTS=(
# 	"xxxx:xxxx:xxxx:xxxx"
# 	"xxxx:xxxx:xxxx:xxxx"
# 	"xxxx:xxxx:xxxx:xxxx"
# )

###########################################################
# ポート定義
###########################################################

SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NET_BIOS=135,137,138,139,445
DHCP=67,68

###########################################################
# 関数
###########################################################

# ip6tablesの初期化, すべてのルールを削除
initialize() 
{
	ip6tables -F # テーブル初期化
	ip6tables -X # チェーンを削除
	ip6tables -Z # パケットカウンタ・バイトカウンタをクリア
	ip6tables -P INPUT   ACCEPT
	ip6tables -P OUTPUT  ACCEPT
	ip6tables -P FORWARD ACCEPT
}

# ルール適用後の処理
finailize()
{
	/sbin/ip6tables-save > /etc/iptables/rules.v6# 設定の保存
	/etc/init.d/netfilter-persistent restart # 保存したもので再起動してみる
	return 0
	return 1
}

# 開発用
if [ "$1" == "dev" ]
then
	ip6tables() { echo "ip6tables $@"; }
	finailize() { echo "finailize"; }
fi

###########################################################
# ip6tablesの初期化
###########################################################
initialize

###########################################################
# ポリシーの決定
###########################################################
ip6tables -P INPUT   DROP # すべてDROP。すべての穴をふさいでから必要なポートを空けていくのが良い。
ip6tables -P OUTPUT  ACCEPT
ip6tables -P FORWARD DROP

###########################################################
# 信頼可能なホストは許可
###########################################################

# ローカルホスト
# lo はローカルループバックのことで自分自身のホストを指す
ip6tables -A INPUT -i lo -j ACCEPT # SELF -> SELF

# ローカルネットワーク
# $LOCAL_NET が設定されていれば LAN上の他のサーバとのやり取りを許可する
if [ "$LOCAL_NET" ]
then
	ip6tables -A INPUT -p tcp -s $LOCAL_NET -j ACCEPT # LOCAL_NET -> SELF
fi

# 信頼可能ホスト
# $ALLOW_HOSTS が設定されていれば そのホストとのやり取りを許可する
if [ "${ALLOW_HOSTS}" ]
then
	for allow_host in ${ALLOW_HOSTS[@]}
	do
		ip6tables -A INPUT -p tcp -s $allow_host -j ACCEPT # allow_host -> SELF
	done
fi

###########################################################
# $DENY_HOSTSからのアクセスは破棄
###########################################################
if [ "${DENY_HOSTS}" ]
then
	for deny_host in ${DENY_HOSTS[@]}
	do
		ip6tables -A INPUT -s $deny_host -m limit --limit 1/s -j LOG --log-prefix "deny_host: "
		ip6tables -A INPUT -s $deny_host -j DROP
	done
fi

###########################################################
# セッション確立後のパケット疎通は許可
###########################################################
ip6tables -A INPUT  -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

###########################################################
# 攻撃対策: Stealth Scan
###########################################################
ip6tables -N STEALTH_SCAN # "STEALTH_SCAN" という名前でチェーンを作る
ip6tables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
ip6tables -A STEALTH_SCAN -j DROP

# ステルススキャンらしきパケットは "STEALTH_SCAN" チェーンへジャンプする
ip6tables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
ip6tables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN

ip6tables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
ip6tables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
ip6tables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN

ip6tables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
ip6tables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
ip6tables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
ip6tables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN

###########################################################
# 攻撃対策: フラグメントパケットによるポートスキャン,DOS攻撃
# namap -v -sF などの対策
###########################################################
ip6tables -A INPUT -f -j LOG --log-prefix 'fragment_packet:'
ip6tables -A INPUT -f -j DROP
 
###########################################################
# 攻撃対策: Ping of Death
###########################################################
# 毎秒1回を超えるpingが10回続いたら破棄
ip6tables -N PING_OF_DEATH # "PING_OF_DEATH" という名前でチェーンを作る
ip6tables -A PING_OF_DEATH -p icmp --icmpv6-type echo-request \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 10 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_PING_OF_DEATH \
         -j RETURN

# 制限を超えたICMPを破棄
ip6tables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death_attack: "
ip6tables -A PING_OF_DEATH -j DROP

# ICMP は "PING_OF_DEATH" チェーンへジャンプ
ip6tables -A INPUT -p icmp --icmpv6-type echo-request -j PING_OF_DEATH

###########################################################
# 攻撃対策: SYN Flood Attack
# この対策に加えて Syn Cookie を有効にすべし。
###########################################################
ip6tables -N SYN_FLOOD # "SYN_FLOOD" という名前でチェーンを作る
ip6tables -A SYN_FLOOD -p tcp --syn \
         -m hashlimit \
         --hashlimit 200/s \
         --hashlimit-burst 3 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_SYN_FLOOD \
         -j RETURN

# 解説
# -m hashlimit                       ホストごとに制限するため limit ではなく hashlimit を利用する
# --hashlimit 200/s                  秒間に200接続を上限にする
# --hashlimit-burst 3                上記の上限を超えた接続が3回連続であれば制限がかかる
# --hashlimit-htable-expire 300000   管理テーブル中のレコードの有効期間（単位：ms
# --hashlimit-mode srcip             送信元アドレスでリクエスト数を管理する
# --hashlimit-name t_SYN_FLOOD       /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
# -j RETURN                          制限以内であれば、親チェーンに戻る

# 制限を超えたSYNパケットを破棄
ip6tables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
ip6tables -A SYN_FLOOD -j DROP

# SYNパケットは "SYN_FLOOD" チェーンへジャンプ
ip6tables -A INPUT -p tcp --syn -j SYN_FLOOD

###########################################################
# 攻撃対策: HTTP DoS/DDoS Attack
###########################################################
ip6tables -N HTTP_DOS # "HTTP_DOS" という名前でチェーンを作る
ip6tables -A HTTP_DOS -p tcp -m multiport --dports $HTTP \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 100 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_HTTP_DOS \
         -j RETURN

# 解説
# -m hashlimit                       ホストごとに制限するため limit ではなく hashlimit を利用する
# --hashlimit 1/s                    秒間1接続を上限とする
# --hashlimit-burst 100              上記の上限を100回連続で超えると制限がかかる
# --hashlimit-htable-expire 300000   管理テーブル中のレコードの有効期間（単位：ms
# --hashlimit-mode srcip             送信元アドレスでリクエスト数を管理する
# --hashlimit-name t_HTTP_DOS        /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
# -j RETURN                          制限以内であれば、親チェーンに戻る

# 制限を超えた接続を破棄
ip6tables -A HTTP_DOS -j LOG --log-prefix "http_dos_attack: "
ip6tables -A HTTP_DOS -j DROP

# HTTPへのパケットは "HTTP_DOS" チェーンへジャンプ
ip6tables -A INPUT -p tcp -m multiport --dports $HTTP -j HTTP_DOS

###########################################################
# 攻撃対策: IDENT port probe
# identを利用し攻撃者が将来の攻撃に備えるため、あるいはユーザーの
# システムが攻撃しやすいかどうかを確認するために、ポート調査を実行
# する可能性があります。
# DROP ではメールサーバ等のレスポンス低下になるため REJECTする
###########################################################
ip6tables -A INPUT -p tcp -m multiport --dports $IDENT -j REJECT --reject-with tcp-reset

###########################################################
# 攻撃対策: SSH Brute Force
# SSHはパスワード認証を利用しているサーバの場合、パスワード総当り攻撃に備える。
# 1分間に5回しか接続トライをできないようにする。
# SSHクライアント側が再接続を繰り返すのを防ぐためDROPではなくREJECTにする。
# SSHサーバがパスワード認証ONの場合、以下をアンコメントアウトする
###########################################################
# ip6tables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --set
# ip6tables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ssh_brute_force: "
# ip6tables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

###########################################################
# 攻撃対策: FTP Brute Force
# FTPはパスワード認証のため、パスワード総当り攻撃に備える。
# 1分間に5回しか接続トライをできないようにする。
# FTPクライアント側が再接続を繰り返すのを防ぐためDROPではなくREJECTにする。
# FTPサーバを立ち上げている場合、以下をアンコメントアウトする
###########################################################
# ip6tables -A INPUT -p tcp --syn -m multiport --dports $FTP -m recent --name ftp_attack --set
# ip6tables -A INPUT -p tcp --syn -m multiport --dports $FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ftp_brute_force: "
# ip6tables -A INPUT -p tcp --syn -m multiport --dports $FTP -m recent --name ftp_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

###########################################################
# 全ホスト(ブロードキャストアドレス、マルチキャストアドレス)宛パケットは破棄
###########################################################
ip6tables -A INPUT -d 192.168.1.255   -j LOG --log-prefix "drop_broadcast: "
ip6tables -A INPUT -d 192.168.1.255   -j DROP
ip6tables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "drop_broadcast: "
ip6tables -A INPUT -d 255.255.255.255 -j DROP
ip6tables -A INPUT -d 224.0.0.1       -j LOG --log-prefix "drop_broadcast: "
ip6tables -A INPUT -d 224.0.0.1       -j DROP

###########################################################
# 全ホスト(ANY)からの入力許可
###########################################################

# ICMP: ping に応答する設定
ip6tables -A INPUT -p icmp -j ACCEPT # ANY -> SELF

# HTTP, HTTPS
ip6tables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT # ANY -> SELF

# SSH: ホストを制限する場合は TRUST_HOSTS に信頼ホストを書き下記をコメントアウトする
ip6tables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT # ANY -> SEL

# FTP
# ip6tables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT # ANY -> SELF

# DNS
ip6tables -A INPUT -p tcp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF
ip6tables -A INPUT -p udp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF

# SMTP
# ip6tables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT # ANY -> SELF

# POP3
# ip6tables -A INPUT -p tcp -m multiport --sports $POP3 -j ACCEPT # ANY -> SELF

# IMAP
# ip6tables -A INPUT -p tcp -m multiport --sports $IMAP -j ACCEPT # ANY -> SELF

###########################################################
# ローカルネットワーク(制限付き)からの入力許可
###########################################################

if [ "$LIMITED_LOCAL_NET" ]
then
	# SSH
	ip6tables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $SSH -j ACCEPT # LIMITED_LOCAL_NET -> SELF
	
	# FTP
	ip6tables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $FTP -j ACCEPT # LIMITED_LOCAL_NET -> SELF

	# MySQL
	ip6tables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $MYSQL -j ACCEPT # LIMITED_LOCAL_NET -> SELF
fi

###########################################################
# 特定ホストからの入力許可
###########################################################

if [ "$ZABBIX_IP" ]
then
	# Zabbix関連を許可
	ip6tables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT # Zabbix -> SELF
fi

###########################################################
# それ以外
# 上記のルールにも当てはまらなかったものはロギングして破棄
###########################################################
ip6tables -A INPUT  -j LOG --log-prefix "drop: "
ip6tables -A INPUT  -j DROP

###########################################################
# SSH 締め出し回避策
# 30秒間スリープしてその後 ip6tables をリセットする。
# SSH が締め出されていなければ、 Ctrl-C を押せるはず。
###########################################################
trap 'finailize && exit 0' 2 # Ctrl-C をトラップする
echo "In 30 seconds ip6tables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
