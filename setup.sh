#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required:  Ubuntu 18.04+
#   Description:  Install IKEV2 VPN for Ubuntu
#   Author: Yanzhe, inspired from quericy version
#   Intro:  https://github.com/YanzheL/one-key-ikev2
#===============================================================================================
clear
VER=2.0.0
echo "#############################################################"
echo "# Install IKEV2 VPN for Ubuntu"
echo "# Intro: https://github.com/YanzheL/ikev2-setup"
echo "#"
echo "# Author:Yanzhe, inspired from quericy version"
echo "#"
echo "# Version:$VER"
echo "#############################################################"
echo ""

__INTERACTIVE=""
if [ -t 1 ] ; then
    __INTERACTIVE="1"
fi

ipvalid() {
  if [ "$1" = "" ]; then return 1; fi
  # Set up local variables
  local ip=${1:-1.2.3.4}
  local IFS=.; local -a a=($ip)
  # Start with a regex format test
  [[ $ip =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  # Test values of quads
  local quad
  for quad in {0..3}; do
    [[ "${a[$quad]}" -gt 255 ]] && return 1
  done
  return 0
}

__green(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;32m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

__red(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;40m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

__yellow(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;33m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}


uninstall_ikev2(){
    service strongswan stop
    uninstall_strongswan
    systemctl daemon-reload
    purge_etc
    iptables_unset
}

# Install IKEV2
install_ikev2(){
    disable_selinux
    check_os
    prerequisite_install
    get_strongswan
    install_strongswan
    import_conf
    ipv4_forward_check
    iptables_set
    systemctl daemon-reload
    systemctl enable strongswan
    service strongswan restart
    success_info
}

upgrade_ikev2(){
    disable_selinux
    check_os
    get_strongswan
    install_strongswan
    systemctl daemon-reload
    service strongswan restart
    success_info
}

# Make sure only root can run our script
rootness(){
    if [[ $EUID -ne 0 ]]; then
        echo -e "$(__red "Error:This script must be run as root!")"
        exit 1
    fi
}

# Disable selinux
disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

# Ubuntu or CentOS
check_os(){
    if  grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        system_str="1"
    else
        echo -e "$(__red "This Script must be running at the Ubuntu")"
        exit 1
    fi
}

have_installed(){
    local installed_version=$(ipsec version|grep -oP '([0-9]+\.[0-9]+\.[0-9]+)(?=/)')
    if [ "$installed_version" != "" ]; then
        return 1
    else
        return 0
    fi
}

pre_confirm(){
    echo "####################################"
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo "Please confirm the information:"
    echo ""
    echo -e "the type of your installation: [$(__green $install_type_str)]"
    echo -e "strongswan version: [$(__green $SWAN_VERSION)]"
    echo ""
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
}

#install necessary lib
prerequisite_install(){
    echo -e "$(__yellow "Installing prerequisites...")"
    clang-9 --version
    if [ $? != "0" ]; then
        cat >/etc/apt/sources.list.d/llvm.list<<-EOF
# i386 not available
deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic main
deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic main
# 6.0
deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-6.0 main
deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-6.0 main
# 7
deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main
deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main
EOF
        apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 \
        && apt -y update \
        && apt -y install clang-9
    fi
    apt -y update \
    && apt -y install libsystemd-dev libpam0g-dev libssl-dev make curl libgmp-dev pkg-config libcurl4-gnutls-dev
    if [ $? -eq 0 ];then
        echo -e "$(__green "Prerequisites installation success!")"
    else
        echo -e "$(__red "Prerequisites installation failed!")"
        exit 1
    fi
}

# Download strongswan
get_strongswan(){
    local strongswan_file="strongswan-${SWAN_VERSION}.tar.gz"
    if [ -f "$strongswan_file" ];then
        echo -e "$strongswan_file [$(__green "found")]"
    else
        echo -e "$(__yellow "Downloading $strongswan_file")"
        if ! wget --no-check-certificate https://download.strongswan.org/$strongswan_file; then
            echo -e "$(__red "Failed to download $strongswan_file")"
            exit 1
        fi
    fi
    tar xzf $strongswan_file
    if [ $? -eq 0 ];then
        echo -e "$(__green "Got $strongswan_file")"
    else
        echo -e "$(__red "Unzip $strongswan_file failed!")"
        exit 1
    fi
}

# configure and install strongswan
install_strongswan(){
    echo -e "$(__yellow "Installing strongswan...")"
    cd $CUR_DIR/strongswan-${SWAN_VERSION}
    local cpu_num=$(cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l)
    export CC=clang-9
    export CXX=clang++-9
    ./configure \
    --enable-addrblock \
    --enable-aesni \
    --enable-attr \
    --enable-af-alg \
    --enable-bypass-lan \
    --enable-certexpire \
    --enable-chapoly \
    --enable-constraints \
    --enable-counters \
    --enable-curl \
    --enable-ctr \
    --enable-curve25519 \
    --enable-dhcp \
    --enable-eap-dynamic \
    --enable-eap-identity \
    --enable-eap-md5 \
    --enable-eap-mschapv2 \
    --enable-eap-peap \
    --enable-eap-radius \
    --enable-eap-tls \
    --enable-eap-tnc \
    --enable-eap-ttls \
    --enable-error-notify \
    --enable-ext-auth \
    --enable-farp \
    --enable-gcm \
    --enable-lookip \
    --enable-newhope \
    --enable-ntru \
    --enable-openssl \
    --enable-pkcs11 \
    --enable-radattr \
    --enable-swanctl \
    --enable-tpm \
    --enable-unity \
    --enable-xauth-eap \
    --enable-xauth-pam \
    --enable-systemd --with-systemdsystemunitdir=/lib/systemd/system \
    && make "-j$cpu_num" \
    && make install 

    if [ $? -eq 0 ];then
        echo -e "$(__green "Strongswan installation success!")"
    else
        echo -e "$(__red "Strongswan installation failed!")"
        exit 1
    fi
}

# configure and install strongswan
uninstall_strongswan(){
    cd $CUR_DIR
    local installed_version=$(ipsec version|grep -oP '([0-9]+\.[0-9]+\.[0-9]+)(?=/)')
    if [ $? -ne 0 ]; then
        echo -e "$(__red "Cannot found a valid strongswan installation")"
        exit 1
    fi
    cd strongswan-$installed_version
    echo -e "$(__yellow "Uninstalling strongswan-${installed_version}...")"
    make uninstall \
    && make clean \
    && cd .. \
    && rm -rf strongswan-${installed_version}*

    if [ $? -eq 0 ];then
        echo -e "$(__green "Strongswan uninstallation success!")"
    else
        echo -e "$(__red "Strongswan uninstallation failed!")"
        exit 1
    fi
}

# import strongswan settings
import_conf(){
    local etc_git="https://github.com/YanzheL/strongswan-conf"
    echo -e "$(__yellow "Fetching strongswan example config files from $etc_git")"
    cd /usr/local/etc
    git clone $etc_git example
    if [ $? -eq 0 ];then
        cp example/*.template ./
        echo -e "$(__green "Strongswan config files imported!")"
    else
        echo -e "$(__red "Strongswan config files import error, you should do this manually later")"
    fi
    cd $CUR_DIR
}

NAT_configure(){
    local use_SNAT_str
    NAT_TYPE="m"
    read -p "Use SNAT could implove the speed,but your server MUST have static ip address, Y|n?" use_SNAT_str
    if [ "$use_SNAT_str" = "n" ]; then
    else
        NAT_TYPE="s"
        echo -e "$(__yellow "ip address info:")"
        ip address
        echo "The above content is the network card information of your VPS."
        echo "[$(__yellow "Important")]Please enter the name of the interface which can be connected to the public network."
        read -p "Network card interface(default_value:eth0):" interface
        if [ "$interface" = "" ]; then
            interface="eth0"
        fi
        local interface_ip="$(ip address show ${interface}|grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+')"
        echo "Some servers has elastic IP (AWS) or mapping IP.In this case,you should input the IP address which is binding in network interface."
        read -p "static ip or network interface ip(default_value:$interface_ip):" static_ip
        if [ "$static_ip" = "" ]; then
            static_ip=$interface_ip
        fi
        until ipvalid "$static_ip"
          do
            read -p "invalid static ip "$static_ip", try again:" static_ip
          done
    fi

    ./nat_add $NAT_TYPE $interface
}


# Purge strongswan settings
purge_etc(){
    local purge
    read -p "Purge settings? (Y|n):" purge
    if [ "$purge" != "n" ]; then
        rm -rf /usr/local/etc
    fi
}

# configure the ipsec.secrets
configure_secrets(){
    echo -e "$(__yellow "Importing default secrets...")"
    cat > /usr/local/etc/ipsec.secrets<<-EOF
: ECDSA p256.lee-service.com.key
Yanzhe %any : EAP "QQ-admin@@1998"
EOF
    echo -e "$(__green "Default secrets imported!")"
}

# iptables check
ipv4_forward_check(){
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then 
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl --system
    fi
}

# iptables set
iptables_set(){
    echo -e "$(__yellow "Importing iptables rules...")"
    $CUR_DIR/iptables_add \
    && /etc/network/if-up.d/iptables
    if [ $? -eq 0 ];then
        echo -e "$(__green "Finished iptables configuration!")"
    else
        echo -e "$(__red "iptablse configuration failed, please check it manually")"
    fi 
}

# iptables set
iptables_unset(){
    echo -e "$(__yellow "Deleting iptables rules...")"
    /etc/network/if-up.d/iptables reverse
    if [ $? -eq 0 ];then
        echo -e "$(__green "Finished iptables restoration!")"
    else
        echo -e "$(__red "iptablse restoration failed, please check it manually")"
    fi 
    rm /etc/network/if-up.d/iptables
}

# echo the success info
success_info(){
    echo "#############################################################"
    echo -e "#"
    echo -e "# [$(__green "Install Complete")]"
    echo -e "# Version:$VER"
    echo -e "# There is the default login info of your IPSec/IkeV2 VPN Service"
    echo -e "$(__green "$(cat /usr/local/etc/ipsec.secrets)")"
    echo -e "# you should change default username and password in$(__green " /usr/local/etc/ipsec.secrets")"
    echo -e "# you cert: $(__green "/usr/local/etc/ipsec.d ")"
    echo -e "#"
    echo -e "#############################################################"
    echo -e ""
}

# Initialization step

rootness
CUR_DIR=`pwd`

case $1 in
    install)
        have_installed
        if [ $? -eq 1 ]; then
            echo -e "$(__red "You have installed a previous version, please uninstall it first")"
            exit 1;
        fi
        install_type_str="Install"
        while [ "$SWAN_VERSION" = "" ]
          do
            read -p "Strongswan Version:" SWAN_VERSION
          done
        pre_confirm
        cd $CUR_DIR
        install_ikev2
        read -p "Install type, s or c:(c)" INSTALL_TYPE
        if [ $INSTALL_TYPE -eq "s" ]; then
            NAT_configure
        fi
        ;;
    upgrade)
        install_type_str="Upgrade"
        while [ "$SWAN_VERSION" = "" ]
          do
            read -p "Strongswan Version:" SWAN_VERSION
          done
        pre_confirm
        cd $CUR_DIR
        upgrade_ikev2
        ;;
    uninstall)
        cd $CUR_DIR
        read -p "Really? (y|N)" really
        if [ "$really" = "y" ]; then
            uninstall_ikev2
        fi
        ;;
    *)
        echo "$(__red "Usage"): one-key-ikev2.sh [install|upgrade|uninstall]"
        exit 1
        ;;
esac
exit 0
