#!/bin/bash
# 公式 user install path (= unmask-release pkg → repo 自動結線 → unmask install) を
# 9 distro でテスト + snapshot rollback で clean state に戻す.
#
# 前提:
#   - hv1 で http.server :8080 永続化済 (= unmask-test-repo.service)
#   - test instance (9100-9109) running
#
# flow (per distro):
#   1. cleanup (= 既存 unmask 系 uninstall, repo file / hosts entry 削除)
#   2. snapshot pre_clean (= clean state)
#   3. /etc/hosts に '192.168.11.151 unmask.sh' 追加
#   4. release pkg を http://unmask.sh:8080/.../unmask-release-* で install
#   5. release pkg の postinstall が生成する repo を baseurl http override
#   6. unmask + unmask-plugin-nginx + unmask-web-nginx install
#   7. systemctl status / unmask-admin healthz
#   8. (FIRE 対象 distro のみ) plugin load + nginx -t + reload + curl で challenge
#   9. rollback to pre_clean → delsnapshot
#
# usage:
#   ./install-test-official.sh                    # 全 9 distro
#   ./install-test-official.sh alma9              # 個別
#   ./install-test-official.sh deb12 ub2404       # 発火 match のみ

set -uo pipefail

HV=hv1.hsts.umic.xyz
SSH_KEY=/home/admin/ansible-playbook/ssh/uic-common-root
HV_SSH=(sudo -n ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
SSH_OPTS=(
  -i "$SSH_KEY"
  -o BatchMode=yes
  -o UserKnownHostsFile=/dev/null
  -o StrictHostKeyChecking=no
  # CentOS 6 sshd は ssh-rsa / ssh-dss しか提供しない (= OpenSSH 8.8+ で disabled by default).
  # 全 VM 共通で legacy 受容モードにする (= 新しい distro には影響なし).
  -o HostKeyAlgorithms=+ssh-rsa,ssh-dss
  -o PubkeyAcceptedAlgorithms=+ssh-rsa
  -o "ProxyCommand=sudo -n ssh -i $SSH_KEY -o BatchMode=yes -W %h:%p root@$HV"
)

REPO_HOST=192.168.11.151
REPO_URL="http://unmask.sh:8080"
RUN_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$RUN_DIR/logs-official"
mkdir -p "$LOG_DIR"

declare -A TEST=(
  [deb13]=9100 [deb12]=9101 [ub2604]=9102 [ub2404]=9103 [alpine]=9104
  [alma10]=9105 [alma9]=9106 [alma8]=9107 [centos7]=9108 [centos6]=9109
)
declare -A FAMILY=(
  [deb13]=deb [deb12]=deb [ub2604]=deb [ub2404]=deb [alpine]=apk
  [alma10]=rpm [alma9]=rpm [alma8]=rpm [centos7]=rpm-eol [centos6]=rpm-eol-2
)
declare -A LABEL=(
  [deb13]="Debian 13" [deb12]="Debian 12"
  [ub2604]="Ubuntu 26.04" [ub2404]="Ubuntu 24.04"
  [alpine]="Alpine Linux 3"
  [alma10]="AlmaLinux 10" [alma9]="AlmaLinux 9" [alma8]="AlmaLinux 8"
  [centos7]="CentOS 7" [centos6]="CentOS 6"
)
# Alpine (= 9104) is now a first-class native-mode target (2026-05-24): gcompat
# pulled in via apk depends lets the glibc-built plugin .so dlopen on Alpine's
# musl-linked nginx.  Earlier comment (= "musl で crash + plugin glibc-built で
# dlopen 不可") is obsolete -- admin is pure-Go static and runs on musl, and
# gcompat closes the dlopen gap.
# rpm の repo path は postinstall script の slug 解決に頼るので URL は almalinux 固定で OK
# (= 全 distribution は almalinux への symlink)
declare -A RPM_MAJ=([alma9]=9 [alma10]=10 [alma8]=8 [centos7]=7 [centos6]=6)

# 発火チェック対象: 独自 ClientHello parser (= 2026-05-13) で OpenSSL 1.0 / 1.1 / 3 全 ABI
# に対応したため、 alma8 (= OpenSSL 1.1) / centos7 / centos6 (= OpenSSL 1.0) も plugin 発火可能.
# Alpine は gcompat で glibc plugin を dlopen するので fire 対象に含める.
declare -A FIRE=(
  [alma9]=1 [alma10]=1 [alma8]=1
  [deb12]=1 [deb13]=1 [ub2404]=1 [ub2604]=1 [alpine]=1
  [centos7]=1 [centos6]=1
)

log()   { printf '[%(%H:%M:%S)T] %s\n' -1 "$*" >&2; }
hv()    { "${HV_SSH[@]}" root@$HV "$@"; }

# CURRENT_KEY: set by run_one() before each VM.  vssh() consults it to decide
# whether to route through the docker-bullseye legacy SSH proxy (= rpm-eol-2
# family / CentOS 6) or the direct path.
CURRENT_KEY=""

# vssh: SSH into the current VM.  Transparently switches to the docker
# bullseye proxy for legacy distros whose OpenSSH 5.3 + OpenSSL 1.0.1e can't
# speak modern KEX.  Any -o flags passed by the caller are silently dropped
# in legacy mode (legacy SSH options are baked into the proxy command).
LEGACY_KEY=/tmp/rsa-legacy/id_rsa
vssh() {
  if [[ "${FAMILY[$CURRENT_KEY]:-}" == "rpm-eol-2" ]]; then
    # Pop leading -o args; first non-flag is target, rest is command.
    local target=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -o) shift 2 ;;
        -*) shift ;;
        *)  target="$1"; shift; break ;;
      esac
    done
    [[ -z "$target" ]] && { echo "vssh (legacy): no target"; return 1; }
    # Quote the remaining command for the inner ssh.  printf %q handles spaces / quotes.
    local cmd=""
    if [[ $# -gt 0 ]]; then
      cmd=$(printf '%q ' "$@")
    fi
    # debian:bullseye container on dev2 (= modern admin host with docker).
    # Inner ssh uses RSA-PEM key + legacy KEX, and reaches the EOL VM via
    # a ProxyCommand that jumps through hv1 (where the test VMs live).
    docker run --rm -i \
      -v "$LEGACY_KEY":/key.rsa:ro \
      -v "$SSH_KEY":/key.ed:ro \
      debian:bullseye sh -c "
apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y openssh-client >/dev/null 2>&1
cp /key.rsa /tmp/k && chmod 600 /tmp/k
cp /key.ed  /tmp/h && chmod 600 /tmp/h
ssh -i /tmp/k -o BatchMode=yes \\
    -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \\
    -o HostKeyAlgorithms=+ssh-rsa,ssh-dss \\
    -o PubkeyAcceptedKeyTypes=+ssh-rsa \\
    -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 \\
    -o ConnectTimeout=15 \\
    -o 'ProxyCommand=ssh -i /tmp/h -o BatchMode=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p root@$HV' \\
    $target $cmd
"
    return $?
  fi
  sudo -n ssh "${SSH_OPTS[@]}" "$@"
}

resolve_ip() {
  local vmid=$1 mac out ip
  mac=$(hv "qm config $vmid 2>/dev/null | grep ^net0:" | grep -oiE '[0-9a-f]{2}(:[0-9a-f]{2}){5}' | tr 'A-Z' 'a-z' | head -1)
  for _ in $(seq 1 10); do
    out=$(hv "qm guest cmd $vmid network-get-interfaces 2>/dev/null") || true
    ip=$(echo "$out" | grep -oE '"ip-address" : "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' | grep -v '127' | head -1 | sed 's/.*"\([0-9.]*\)"/\1/')
    [ -n "${ip:-}" ] && { echo "$ip"; return 0; }
    if [ -n "$mac" ]; then
      ip=$(hv "grep -i '$mac' /var/lib/misc/dnsmasq.leases 2>/dev/null | awk '{print \$3}'")
      [ -n "${ip:-}" ] && { echo "$ip"; return 0; }
    fi
    sleep 5
  done
  return 1
}

cleanup_rpm() {
  local ip=$1
  # vssh は bash function. timeout でラップは不可. SSH 自体に ConnectTimeout=30 +
  # ServerAliveInterval / ServerAliveCountMax が効くので、 hang してもいずれ切れる.
  vssh -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
       root@$ip 'set +e
    if [ -f /etc/centos-release ]; then
      for f in /etc/yum.repos.d/CentOS-*.repo; do
        [ -f "$f" ] && sed -i "s|^mirrorlist=|#mirrorlist=|; s|^#baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|" "$f"
      done
    fi
    # 旧 unmask 系 GPG key を rpmdb から削除 (= 旧 key で署名された BAD-sig 残骸対策).
    rpm -qa gpg-pubkey 2>/dev/null | while read k; do
      rpm -qi "$k" 2>/dev/null | grep -qi unmask && rpm -e --noscripts --noverify "$k" 2>/dev/null
    done
    # rpm -e で remove. --nosignature --nodigest で rpmdb iterator の skip 対策.
    # --allmatches で複数 version も一気に. --justdb fallback も用意.
    for p in unmask unmask-plugin-nginx unmask-web-nginx unmask-release; do
      rpm --nosignature --nodigest -e --noscripts --nodeps --allmatches "$p" 2>&1 | head -3
      if rpm --nosignature --nodigest -q "$p" >/dev/null 2>&1; then
        rpm --nosignature --nodigest -e --justdb --noscripts --nodeps --allmatches "$p" 2>&1 | head -3
      fi
    done
    # 最後に rpmdb rebuild (= BAD-sig 残骸 entry を rebuild 後の DB から落とす).
    rpm --rebuilddb 2>&1 | head -2
    # binary / config 残骸の force 削除 (= rpm 管理外も含めて全部)
    rm -f /etc/yum.repos.d/unmask.repo /usr/share/nginx/modules/unmask*.conf
    rm -rf /etc/unmask /var/lib/unmask /usr/share/unmask /usr/sbin/unmask-admin
    rm -f /etc/init.d/unmask-admin /usr/lib/systemd/system/unmask-admin.service
    find /usr -name "ngx_http_unmask_module*.so" -delete 2>/dev/null
    rm -f /usr/share/nginx/modules/unmask-load.conf
    rm -f /usr/lib/systemd/system/unmask-aggregate.{service,timer}
    grep -v "unmask.sh" /etc/hosts > /tmp/hosts.new && mv /tmp/hosts.new /etc/hosts
    if command -v dnf >/dev/null; then dnf clean all >/dev/null; else yum clean all >/dev/null; fi
    # 状態確認 (= rpmdb から消えていること & file が消えていること)
    echo "--- cleanup verify ---"
    rpm -q unmask unmask-plugin-nginx unmask-web-nginx unmask-release 2>&1 | head -4
    ls /usr/sbin/unmask-admin /etc/unmask 2>&1 | head -2
  '
}

cleanup_deb() {
  local ip=$1
  vssh -o ConnectTimeout=30 root@$ip 'set +e
    export DEBIAN_FRONTEND=noninteractive
    # broken state 修復先行 (= 前回試験で plugin preinst fail で broken install state 残ると以降 apt が止まる)
    rm -f /etc/apt/sources.list.d/unmask.list /etc/apt/sources.list.d/unmask.sources
    apt-get install -fy 2>&1 | tail -3
    dpkg --configure -a 2>&1 | tail -3
    apt-get purge -y unmask unmask-plugin-nginx unmask-web-nginx unmask-release 2>&1 | tail -3
    dpkg --purge unmask unmask-plugin-nginx unmask-web-nginx unmask-release 2>&1 | tail -3
    rm -f /etc/apt/keyrings/unmask*
    rm -rf /etc/unmask /var/lib/unmask /usr/share/unmask
    rm -rf /etc/systemd/system/unmask-admin.service.d
    rm -f /etc/nginx/modules-enabled/unmask.conf /etc/nginx/modules-available/unmask.conf
    # plugin .so の実体も削除 (= 上記 rpm 系と同理由)
    rm -f /usr/lib/nginx/modules/ngx_http_unmask_module.so
    rm -f /usr/lib64/nginx/modules/ngx_http_unmask_module.so
    rm -f /usr/share/nginx/modules/ngx_http_unmask_module.so
    grep -v "unmask.sh" /etc/hosts > /tmp/hosts.new && mv /tmp/hosts.new /etc/hosts
    apt-get clean
    rm -f /var/cache/apt/archives/unmask*.deb
  '
}

cleanup_apk() {
  local ip=$1
  vssh -o ConnectTimeout=30 root@$ip 'set +e
    apk del unmask unmask-plugin-nginx unmask-web-nginx unmask-release 2>&1 | tail -3
    sed -i "/unmask/d" /etc/apk/repositories
    rm -f /etc/apk/repositories.d/unmask.list /etc/apk/repositories.d/unmask.list.apk-new
    rm -f /etc/apk/keys/oss@unmask.sh-260509.rsa.pub /etc/apk/keys/unmask-release*
    # SysVinit/OpenRC init script 残骸を完全削除 (= 新 apk の postinstall で正しく symlink 貼り直し)
    rm -f /etc/init.d/unmask-admin
    rm -rf /etc/unmask /var/lib/unmask /usr/share/unmask
    grep -v "unmask.sh" /etc/hosts > /tmp/hosts.new && mv /tmp/hosts.new /etc/hosts
  '
}

install_rpm() {
  local ip=$1 key=$2
  local maj=${RPM_MAJ[$key]:-9}
  vssh -o ConnectTimeout=30 root@$ip "set +e
    echo '--- install_rpm: pre-install state ---'
    rpm -qa 'unmask*' 2>&1 | head -5
    echo '$REPO_HOST unmask.sh' >> /etc/hosts
    if command -v dnf >/dev/null; then DNF=dnf; else DNF=yum; fi
    # CentOS 7 (= yum) で rpm DB corruption (= Unknown error during transaction
    # test in RPM) が出るので、 install 前に rpmdb 再構築 + GPG check 強制 skip.
    rpm --rebuilddb 2>/dev/null || true
    \$DNF install -y --nogpgcheck $REPO_URL/rpm/x86_64/RPMS/unmask-release-0.1.0-1.noarch.rpm 2>&1 | tail -5
    sed -i 's|https://unmask.sh/dl|$REPO_URL|; s|gpgcheck=1|gpgcheck=0|' /etc/yum.repos.d/unmask.repo
    # alma8 / RHEL 8: default nginx module stream is 1.14 (= built without
    # --with-compat).  Third-party plugins can't load with that.  Switch
    # to 1.24 from the same AppStream so no external repo is required.
    if [ '$key' = 'alma8' ]; then
      \$DNF module reset -y nginx 2>&1 | tail -2
      \$DNF module install -y nginx:1.24 2>&1 | tail -2
    else
      \$DNF install -y nginx 2>&1 | tail -2
    fi
    \$DNF install -y --nogpgcheck unmask unmask-plugin-nginx unmask-web-nginx 2>&1 | tail -8
    if command -v systemctl >/dev/null; then
      systemctl status unmask-admin --no-pager 2>&1 | sed -n '1,5p'
      systemctl is-active unmask-admin || true
    else
      service unmask-admin status 2>&1 | head -3
    fi
    # service start race 回避: 8765 が listen 始めるまで最大 15 秒待つ
    # (admin は migrate → render-nginx → serve の順なので sqlite migrate 後の bind に
    # 数秒かかる. previous 5 秒では healthz=000 が頻発)
    for _ in \$(seq 1 15); do
      ss -nlt 2>/dev/null | grep -q ':8765 ' && break
      sleep 1
    done
    curl -sk -m 5 -o /dev/null -w 'admin healthz: %{http_code}\n' http://127.0.0.1:8765/unmask/healthz
  "
}

install_deb() {
  local ip=$1 key=$2
  vssh -o ConnectTimeout=30 root@$ip "set +e
    export DEBIAN_FRONTEND=noninteractive
    echo '$REPO_HOST unmask.sh' >> /etc/hosts
    apt-get install -y wget 2>&1 | tail -2
    wget -q -O /tmp/unmask-release.deb $REPO_URL/deb/pool/main/u/unmask/unmask-release_0.1.0_all.deb
    apt-get install -y /tmp/unmask-release.deb 2>&1 | tail -5
    # 生成された repo file (= postinstall script による) の URL 書換え
    for f in /etc/apt/sources.list.d/unmask.list /etc/apt/sources.list.d/unmask.sources; do
      [ -f \$f ] && {
        echo \"--- \$f (before) ---\"; cat \$f
        sed -i 's|https://unmask.sh/dl|$REPO_URL|' \$f
        # 署名 trust skip (= [trusted=yes])
        if grep -q '^deb ' \$f 2>/dev/null && ! grep -q '\[trusted' \$f; then
          sed -i 's|^deb |deb [trusted=yes] |' \$f
        fi
        if grep -q '^Types' \$f 2>/dev/null && ! grep -qi '^Trusted' \$f; then
          echo 'Trusted: yes' >> \$f
        fi
        echo \"--- \$f (after) ---\"; cat \$f
      }
    done
    apt-get update -qq 2>&1 | tail -3
    # 3 stage install (= 3 個一気だと dpkg unpack 順序で plugin が main より先に preinst 走って fail する事例あり)
    apt-get install -y unmask 2>&1 | tail -8
    apt-get install -y unmask-plugin-nginx 2>&1 | tail -5
    apt-get install -y unmask-web-nginx 2>&1 | tail -5
    systemctl status unmask-admin --no-pager 2>&1 | sed -n '1,5p'
    # wait up to 15s for :8765 to bind (= migrate → render-nginx → serve sequence)
    for _ in \$(seq 1 15); do
      ss -nlt 2>/dev/null | grep -q ':8765 ' && break
      sleep 1
    done
    curl -sk -m 5 -o /dev/null -w 'admin healthz: %{http_code}\n' http://127.0.0.1:8765/unmask/healthz
  "
}

install_apk() {
  local ip=$1 key=$2
  vssh -o ConnectTimeout=30 root@$ip "set +e
    echo '$REPO_HOST unmask.sh' >> /etc/hosts
    apk add --no-cache wget curl 2>&1 | tail -1
    wget -q -O /tmp/unmask-release.apk $REPO_URL/apk/main/x86_64/unmask-release-latest.apk
    apk add --allow-untrusted /tmp/unmask-release.apk 2>&1 | tail -5
    # postinstall は /etc/apk/repositories と /etc/apk/repositories.d/unmask.list 両方に
    # 配置する場合あり (= 22:18 [A] で repositories.d/ static 同梱に変更. apk-tools v3 は両 file 読む).
    sed -i 's|https://unmask.sh/dl|$REPO_URL|' /etc/apk/repositories
    [ -f /etc/apk/repositories.d/unmask.list ] && \
      sed -i 's|https://unmask.sh/dl|$REPO_URL|' /etc/apk/repositories.d/unmask.list
    cat /etc/apk/repositories | grep -i unmask
    cat /etc/apk/repositories.d/unmask.list 2>/dev/null
    # snapshot rollback で apk cache に古い APKINDEX 残ってる場合があるので強制 refresh
    rm -rf /etc/apk/cache/* /var/cache/apk/APKINDEX*
    apk update 2>&1 | tail -3
    apk add --force-overwrite --force-refresh unmask unmask-plugin-nginx unmask-web-nginx 2>&1 | tail -10
    # workaround: apk hook 環境で main pkg postinstall の OpenRC symlink 貼る処理が走らない事例あり.
    # 手動で symlink + rc-update add (= 真の fix は terminal A 領分継続).
    [ -f /usr/share/unmask/init/unmask-admin.openrc ] && \
      ln -sf /usr/share/unmask/init/unmask-admin.openrc /etc/init.d/unmask-admin && \
      rc-update add unmask-admin default 2>/dev/null
    rc-service unmask-admin start 2>&1 | tail -2
    rc-status default 2>/dev/null | grep unmask-admin
    # wait up to 15s for :8765 to bind
    for _ in \$(seq 1 15); do
      ss -nlt 2>/dev/null | grep -q ':8765 ' && break
      sleep 1
    done
    curl -sk -m 5 -o /dev/null -w 'admin healthz: %{http_code}\n' http://127.0.0.1:8765/unmask/healthz
  "
}

fire_check() {
  local ip=$1 key=$2
  vssh -o ConnectTimeout=30 root@$ip "set +e
    # admin daemon は startup で nginx-render しないので fire 前に明示 render.
    # これで /etc/unmask/native/http.inc に \$effective_ja4 等の map が出る.
    echo '--- config.yml nginx section ---'
    awk '/^nginx:/{f=1;print;next} /^[a-z]/{f=0} f' /etc/unmask/config.yml 2>&1 | head -10
    echo '--- render-nginx STDERR + STDOUT (2>&1) ---'
    unmask-admin render-nginx -out-dir /etc/unmask
    rc=\$?
    echo \"render-nginx exit=\$rc\"
    echo '--- ls -la /etc/unmask/ ---'
    ls -la /etc/unmask/ 2>&1 | head -15
    echo '--- ls -la /etc/unmask/native/ ---'
    ls -la /etc/unmask/native/ 2>&1
    echo '--- find /etc/unmask -name http.inc -or -name server.inc -or -name protect.inc ---'
    find /etc/unmask -type f \( -name 'http.inc' -o -name 'server.inc' -o -name 'protect.inc' -o -name '*-rendered*' \) -printf '%p %s\n' 2>&1
    echo '--- effective_ja4 count ---'
    grep -c effective_ja4 /etc/unmask/native/http.inc 2>&1
    echo '--- 00-unmask.conf symlink target ---'
    readlink /etc/nginx/conf.d/00-unmask.conf 2>&1
    NGINX_VER=\$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    # 新 postinstall (= 2026-05-13 multi-OpenSSL fat package) は host の libcrypto を ldd
    # で検出 → /usr/share/unmask/plugin/openssl{10,11,3}/ から best match の .so を選んで
    # 既に nginx の --modules-path に cp 済. fire_check はそれを参照するだけで OK.
    MODULES_PATH=\$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
    PLUGIN=\$MODULES_PATH/ngx_http_unmask_module.so
    [ ! -f \"\$PLUGIN\" ] && PLUGIN=\"\"
    echo \"NGINX_VER=\$NGINX_VER MODULES_PATH=\$MODULES_PATH PLUGIN=\$PLUGIN\"
    [ -z \"\$PLUGIN\" ] && { echo '(no matching plugin)'; exit 1; }
    # plugin の libcrypto link を確認 (= ABI mismatch debug 用)
    ldd \"\$PLUGIN\" 2>&1 | grep -E 'libssl|libcrypto' | head -3
    # module config dir (= deb は modules-enabled, rpm/alpine は usr/share/nginx/modules).
    # nginx.conf が実際 include してる path を優先.
    MOD_DIR=
    if grep -q '/etc/nginx/modules-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
      MOD_DIR=/etc/nginx/modules-enabled
    elif grep -q '/usr/share/nginx/modules' /etc/nginx/nginx.conf 2>/dev/null; then
      MOD_DIR=/usr/share/nginx/modules
    else
      for d in /etc/nginx/modules-enabled /usr/share/nginx/modules /etc/nginx/conf.d; do
        [ -d \$d ] && MOD_DIR=\$d && break
      done
    fi
    echo \"MOD_DIR=\$MOD_DIR\"
    # plugin postinstall is already drops a load_module conf (= 50-mod-unmask.conf).
    # Remove any pre-existing unmask*.conf in MOD_DIR before writing our own to
    # avoid \"module is already loaded\" duplicate-load error from nginx.
    rm -f \$MOD_DIR/*unmask*.conf
    echo \"load_module \$PLUGIN;\" > \$MOD_DIR/unmask-load.conf
    echo '--- MOD_DIR contents after write ---'
    ls -la \$MOD_DIR/ 2>&1 | head -10
    # docs に従い user vhost に protect.inc を include する形を再現する.  distro 既定の
    # default server を消さず、 fire_check 用の test vhost を別ファイルで上書きで生成する.
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.disabled
    rm -f /etc/nginx/conf.d/default.conf /etc/nginx/http.d/default.conf
    # Pick the include dir that lives inside http {} -- conf.d/ is correct on
    # RHEL/Debian but main-scope on Alpine, where http.d/ is the http {} dir.
    SITES_DIR=/etc/nginx/conf.d
    if grep -q '/etc/nginx/sites-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
        SITES_DIR=/etc/nginx/sites-enabled
    elif [ -d /etc/nginx/http.d ] && awk '
        /\<http[[:space:]]*\{/ { in_http=1 }
        in_http && /include[[:space:]]+\/etc\/nginx\/http\.d\// { found=1 }
        /^\}/ { in_http=0 }
        END { exit !found }
      ' /etc/nginx/nginx.conf 2>/dev/null; then
        SITES_DIR=/etc/nginx/http.d
    fi
    echo \"SITES_DIR=\$SITES_DIR\"
    mkdir -p \$SITES_DIR
    cat > \$SITES_DIR/zz-fire-test.conf <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    include /etc/unmask/auth_request/server.inc;
    location / {
        include /etc/unmask/auth_request/protect.inc;
        # try_files runs in PRECONTENT phase (= after auth_request's ACCESS),
        # so auth_request gets a chance to fire before this is hit.  When
        # auth_request returns 200 (= pass), try_files looks for index.html
        # which fire_check pre-populates below — gives http=200 for the pass
        # case.  When auth_request returns 401, error_page in protect.inc
        # rewrites to /unmask/challenge/ which admin serves as challenge HTML.
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
    # Populate /var/www/html so try_files can serve index.html when
    # auth_request passes.  Without this the pass case lands on the
    # naked nginx 404 page and the curl test reports http=404.
    mkdir -p /var/www/html
    echo '[unmask fire ok] (= auth_request passed → static served)' > /var/www/html/index.html
    nginx -t 2>&1 | tail -5
    if command -v systemctl >/dev/null; then
      systemctl restart nginx 2>&1 | tail -2
    else
      service nginx restart 2>&1 | tail -2
    fi
    # listen :80 まで最大 30 秒待つ
    LISTEN=
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
      LISTEN=\$(ss -nlt 2>/dev/null | grep -E ':80 ' || netstat -nlt 2>/dev/null | grep ':80 ')
      [ -n \"\$LISTEN\" ] && break
      sleep 1
    done
    echo \"LISTEN=\$LISTEN\"
    if [ -z \"\$LISTEN\" ]; then
      echo '--- nginx status (no listen) ---'
      if command -v systemctl >/dev/null; then
        systemctl status nginx --no-pager 2>&1 | head -15
      else
        service nginx status 2>&1 | head -10
      fi
      echo '--- nginx conf.d ls ---'
      ls /etc/nginx/conf.d /etc/nginx/sites-enabled 2>&1 || true
      echo '--- nginx -T (listen lines) ---'
      nginx -T 2>/dev/null | grep -iE 'listen|server_name' | head -20
    fi
    echo '--- curl with curl/8.0 UA ---'
    curl -sk -A 'curl/8.0' -m 5 -o /tmp/resp.html -w 'http=%{http_code} size=%{size_download}\n' http://127.0.0.1/
    head -5 /tmp/resp.html 2>/dev/null | tr -d '\r'
    grep -ioE 'challenge|_bv|unmask|pow|verifying' /tmp/resp.html 2>/dev/null | sort -u
  "
}

snap_take() {
  local vmid=$1 name=$2
  # 既存 snapshot は古い cleanup の結果. delsnapshot が thinpool lock 等で
  # 稀に fail するので retry. fail で残骸あると新 snapshot が取れず古い state に rollback される.
  hv "
    if qm listsnapshot $vmid 2>/dev/null | grep -q $name; then
      for i in 1 2 3 4 5; do
        qm delsnapshot $vmid $name 2>&1 && break
        sleep 2
      done
    fi
    qm snapshot $vmid $name --description 'pre official install path test'
  "
}

snap_rollback() {
  local vmid=$1 name=$2
  hv "qm rollback $vmid $name; sleep 3; qm start $vmid"
}

snap_del() {
  local vmid=$1 name=$2
  hv "qm delsnapshot $vmid $name 2>&1 || true"
}

run_one() {
  local key=$1
  local vmid=${TEST[$key]}
  local family=${FAMILY[$key]}
  local label=${LABEL[$key]}
  local logf="$LOG_DIR/$key.log"
  : >"$logf"

  # vssh consults CURRENT_KEY to decide whether to route SSH through the
  # docker-bullseye legacy proxy (= rpm-eol-2 / CentOS 6).
  CURRENT_KEY="$key"

  log "=== START $key ($label, family=$family) → $logf ==="

  local ip
  ip=$(resolve_ip $vmid) || { echo "[$key] no IP" | tee -a "$logf"; return 1; }
  log "[$key] IP=$ip"
  echo "IP=$ip" >>"$logf"

  log "[$key] cleanup"
  case "$family" in
    rpm|rpm-eol|rpm-eol-2) cleanup_rpm "$ip" >>"$logf" 2>&1 ;;
    deb)                   cleanup_deb "$ip" >>"$logf" 2>&1 ;;
    apk)                   cleanup_apk "$ip" >>"$logf" 2>&1 ;;
  esac

  log "[$key] snapshot pre_clean"
  snap_take $vmid pre_clean >>"$logf" 2>&1

  log "[$key] install via official path"
  case "$family" in
    rpm|rpm-eol|rpm-eol-2) install_rpm "$ip" "$key" >>"$logf" 2>&1 ;;
    deb)                   install_deb "$ip" "$key" >>"$logf" 2>&1 ;;
    apk)                   install_apk "$ip" "$key" >>"$logf" 2>&1 ;;
  esac

  if [ -n "${FIRE[$key]:-}" ]; then
    log "[$key] FIRE check"
    echo "=== FIRE CHECK ===" >>"$logf"
    fire_check "$ip" "$key" >>"$logf" 2>&1
  fi

  log "[$key] rollback to pre_clean"
  snap_rollback $vmid pre_clean >>"$logf" 2>&1
  snap_del $vmid pre_clean >>"$logf" 2>&1

  log "[$key] DONE"
}

keys=("$@")
# centos6 (= rpm-eol-2) requires the docker-bullseye legacy SSH proxy whose
# nested quoting breaks `"`-literals in cleanup_rpm / fire_check bodies.
# Until that quoting is reworked (= heredoc + base64 round-trip, or rewriting
# the bodies to be `"`-free), centos6 is verified manually per the
# [[reference_centos6_support]] memory and is not part of the default run.
# Pass `centos6` explicitly to opt in.
[ ${#keys[@]} -eq 0 ] && keys=(alma9 alma10 alma8 deb12 deb13 ub2404 ub2604 centos7 alpine)

declare -a OK=() FAIL=() FIRED=()
for k in "${keys[@]}"; do
  if [ -z "${TEST[$k]:-}" ]; then echo "unknown: $k"; continue; fi
  if ( run_one "$k" ); then
    OK+=("$k")
    [ -n "${FIRE[$k]:-}" ] && FIRED+=("$k")
  else
    FAIL+=("$k")
  fi
done

echo
echo "=== summary ==="
echo "install OK : ${OK[*]:-(none)}"
echo "install FAIL: ${FAIL[*]:-(none)}"
echo "fire-checked: ${FIRED[*]:-(none)}"
[ ${#FAIL[@]} -eq 0 ]
