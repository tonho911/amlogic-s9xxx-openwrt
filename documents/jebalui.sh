#!/bin/bash
#file manager
#!/bin/bash
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
purple="\e[0;33m"
# ===================
clear
  # // Exporint IP AddressInformation
export IP=$( curl -sS icanhazip.com )

# // Clear Data
clear
clear && clear && clear
clear;clear;clear

# // Checking Os Architecture
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# // Checking System
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
    exit 1
fi

# // IP Address Validating
if [[ $IP == "" ]]; then
    echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successfull
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
clear
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear

colorized_echo() {
    local color=$1
    local text=$2
    
    case $color in
        "red")
        printf "\e[91m${text}\e[0m\n";;
        "green")
        printf "\e[92m${text}\e[0m\n";;
        "yellow")
        printf "\e[93m${text}\e[0m\n";;
        "blue")
        printf "\e[94m${text}\e[0m\n";;
        "magenta")
        printf "\e[95m${text}\e[0m\n";;
        "cyan")
        printf "\e[96m${text}\e[0m\n";;
        *)
            echo "${text}"
        ;;
    esac
}

# Check if the script is run as root
if [ "$(id -u)" != "0" ]; then
    colorized_echo red "Error: Skrip ini harus dijalankan sebagai root."
    exit 1
fi

# Check supported operating system
supported_os=false

if [ -f /etc/os-release ]; then
    os_name=$(grep -E '^ID=' /etc/os-release | cut -d= -f2)
    os_version=$(grep -E '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

    if [ "$os_name" == "debian" ] && [ "$os_version" == "12" ]; then
        supported_os=true
    elif [ "$os_name" == "debian" ] && [ "$os_version" == "11" ]; then
        supported_os=true
    fi
fi

if [ "$supported_os" != true ]; then
    colorized_echo red "Error: Skrip ini hanya support di Debian 12 dan Ubuntu 22.04. Mohon gunakan OS yang di support."
    exit 1
fi
apt install sudo curl jq unzip -y
# Fungsi untuk menambahkan repo Debian 12
addDebian12Repo() {
    echo "#mirror_kambing-sysadmind deb12
deb http://kartolo.sby.datautama.net.id/debian/ bookworm contrib main non-free non-free-firmware
deb http://kartolo.sby.datautama.net.id/debian/ bookworm-updates contrib main non-free non-free-firmware
deb http://kartolo.sby.datautama.net.id/debian/ bookworm-proposed-updates contrib main non-free non-free-firmware
deb http://kartolo.sby.datautama.net.id/debian/ bookworm-backports contrib main non-free non-free-firmware
deb http://kartolo.sby.datautama.net.id/debian-security/ bookworm-security contrib main non-free non-free-firmware" | sudo tee /etc/apt/sources.list > /dev/null
}

# Fungsi untuk menambahkan repo Ubuntu 22.04
addUbuntu2004Repo() {
    echo "#mirror buaya klas 22.04
deb http://kebo.pens.ac.id/ubuntu/ jammy main restricted universe multiverse
deb http://kebo.pens.ac.id/ubuntu/ jammy-updates main restricted universe multiverse
deb http://kebo.pens.ac.id/ubuntu/ jammy-security main restricted universe multiverse
deb http://kebo.pens.ac.id/ubuntu/ jammy-backports main restricted universe multiverse
deb http://kebo.pens.ac.id/ubuntu/ jammy-proposed main restricted universe multiverse" | sudo tee /etc/apt/sources.list > /dev/null
}

# Mendapatkan informasi kode negara dan OS
COUNTRY_CODE=$(curl -s https://ipinfo.io/country)
OS=$(lsb_release -si)

# Pemeriksaan IP Indonesia
if [[ "$COUNTRY_CODE" == "ID" ]]; then
    colorized_echo green "IP Indonesia terdeteksi, menggunakan repositories lokal Indonesia"

    # Menanyakan kepada pengguna apakah ingin menggunakan repo lokal atau repo default
    read -p "Apakah Anda ingin menggunakan repo lokal Indonesia? (y/n): " use_local_repo

    if [[ "$use_local_repo" == "y" || "$use_local_repo" == "Y" ]]; then
        # Pemeriksaan OS untuk menambahkan repo yang sesuai
        case "$OS" in
            Debian)
                VERSION=$(lsb_release -sr)
                if [ "$VERSION" == "12" ]; then
                    addDebian12Repo
                else
                    colorized_echo red "Versi Debian ini tidak didukung."
                fi
                ;;
            Ubuntu)
                VERSION=$(lsb_release -sr)
                if [ "$VERSION" == "20.04" ]; then
                    addUbuntu2004Repo
                else
                    colorized_echo red "Versi Ubuntu ini tidak didukung."
                fi
                ;;
            *)
                colorized_echo red "Sistem Operasi ini tidak didukung."
                ;;
        esac
    else
        colorized_echo yellow "Menggunakan repo bawaan VM."
        # Tidak melakukan apa-apa, sehingga repo bawaan VM tetap digunakan
    fi
else
    colorized_echo yellow "IP di luar Indonesia."
    # Lanjutkan dengan repo bawaan OS
fi
mkdir -p /etc/data

#email
read -rp "Masukkan Email anda: " email
echo "$email" > /etc/data/email

#domain
read -rp "Masukkan Domain: " domain
echo "$domain" > /etc/data/domain
domain=$(cat /etc/data/domain)

#token
while true; do
    read -rp "Masukkan UsernamePanel (hanya huruf dan angka): " userpanel

    # Memeriksa apakah userpanel hanya mengandung huruf dan angka
    if [[ ! "$userpanel" =~ ^[A-Za-z0-9]+$ ]]; then
        echo "UsernamePanel hanya boleh berisi huruf dan angka. Silakan masukkan kembali."
    elif [[ "$userpanel" =~ [Aa][Dd][Mm][Ii][Nn] ]]; then
        echo "UsernamePanel tidak boleh mengandung kata 'admin'. Silakan masukkan kembali."
    else
        echo "$userpanel" > /etc/data/userpanel
        break
    fi
done

read -rp "Masukkan PasswordPanel: " passpanel
echo "$passpanel" > /etc/data/passpanel

#nameregis
read -rp "Masukkan ISP VPS: " nama
echo "$nama" > /etc/data/nama

#Pass Backup
read -rp "Masukkan Pass untuk file Backup: " fileb
echo "$fileb" > /etc/data/passbackup

# Function to validate port input
while true; do
  read -rp "Masukkan Default Port untuk Marzban Dashboard GUI (selain 443 dan 80): " port

  if [[ "$port" -eq 443 || "$port" -eq 80 ]]; then
    echo "Port $port tidak valid. Silakan isi dengan port selain 443 atau 80."
  else
    echo "Port yang Anda masukkan adalah: $port"
    break
  fi
done

#install sysctl
wget -O /etc/sysctl.conf "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/sysctl.conf"

# gunakan ipv6 atau tidak
echo "1. Aktifkan IPv6"
echo "2. Nonaktifkan IPv6"
read -rp "Masukkan nomor pilihan (1 atau 2): " choice

case $choice in
    1)
        echo "Mengaktifkan IPv6"
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.forwarding = 1" >> /etc/sysctl.conf
        sudo sysctl -p  # Reload konfigurasi
        ;;
    2)
        echo "Menonaktifkan IPv6"
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        sudo sysctl -p  # Reload konfigurasi
        ;;
    *)
        echo "Pilihan tidak valid. Pilih 1 atau 2."
        ;;
esac

#Preparation
clear
cd;
apt-get update;

#Remove unused Module
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

#install benchmark
wget -O /usr/bin/bench "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/bench.sh" && chmod +x /usr/bin/bench

#install toolkit
sudo apt-get install git libio-socket-inet6-perl libsocket6-perl libcrypt-ssleay-perl libnet-libidn-perl perl libio-socket-ssl-perl libwww-perl libpcre3 libpcre3-dev zlib1g-dev dbus iftop zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr dnsutils at htop iptables bsdmainutils cron lsof lnav -y

#Install lolcat
apt-get install -y ruby;
gem install lolcat;

#Set Timezone GMT+7
timedatectl set-timezone Asia/Jakarta;

#Install Marzban
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/marzban.sh)" @ install

#install subs
wget -O /opt/marzban/index.html "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/index.html"

#install env
wget -O /opt/marzban/.env "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/env"

#install compose
wget -O /opt/marzban/docker-compose.yml "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/docker-compose.yml"

#install assets & core
mkdir -p /etc/autokill/logs
mkdir -p /etc/autokill/penalty_logs
mkdir -p /var/lib/marzban/assets
mkdir -p /var/lib/marzban/core
wget "https://github.com/ueu6969/crot/raw/refs/heads/node/core/xray.tar.gz" && tar zxvf xray.tar.gz -C /var/lib/marzban/core
chmod +x /var/lib/marzban/core/xray
rm -f /root/xray.tar.gz

#profile
echo -e 'profile' >> /root/.profile
wget -O /usr/bin/profile "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/profile";
chmod +x /usr/bin/profile
apt install neofetch -y

#Install VNSTAT
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/utilitas/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install 
cd
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz 
rm -rf /root/vnstat-2.6

# Swap RAM 1GB
wget https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/swap.sh -O swap
sh swap 1G
rm swap

#Install Speedtest
curl -s https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/script.deb.sh | sudo bash
sudo apt-get install speedtest -y

#install gotop
git clone --depth 1 https://github.com/ueu6969/gotop /tmp/gotop
/tmp/gotop/scripts/download.sh
cp /root/gotop /usr/bin/
chmod +x /usr/bin/gotop
cd

#install nginx
mkdir -p /var/log/nginx
touch /var/log/nginx/access.log
touch /var/log/nginx/error.log
wget -O /opt/marzban/nginx.conf "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/nginx.conf"
wget -O /opt/marzban/default.conf "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/vps.conf"
wget -O /opt/marzban/xray.conf "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/xray.conf"
mkdir -p /var/www/html
echo "<pre>Setup by AutoScript tonho dalua</pre>" > /var/www/html/index.html

#install socat
apt install iptables -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion -y

#install cert
curl https://get.acme.sh | sh -s email=$email
/root/.acme.sh/acme.sh --server letsencrypt --register-account -m $email --issue -d $domain --standalone -k ec-256 --debug
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /var/lib/marzban/xray.crt --keypath /var/lib/marzban/xray.key --ecc
rm /var/lib/marzban/xray_config.json
wget -O /var/lib/marzban/xray_config.json "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/config/xray_config.json"

#install command
cd /usr/bin
#List Trojan
wget -O addtrws "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addtrws" && chmod +x addtrws
wget -O addtrhu "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addtrhu" && chmod +x addtrhu
wget -O addtrgrpc "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addtrgrpc" && chmod +x addtrgrpc
wget -O addtrojan "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addtrojan" && chmod +x addtrojan
#Lits VMess
wget -O addvmws "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvmws" && chmod +x addvmws
wget -O addvmhu "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvmhu" && chmod +x addvmhu
wget -O addvmgrpc "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvmgrpc" && chmod +x addvmgrpc
wget -O addvmess "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvmess" && chmod +x addvmess
#List VLess
wget -O addvlws "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvlws" && chmod +x addvlws
wget -O addvlhu "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvlhu" && chmod +x addvlhu
wget -O addvlgrpc "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvlgrpc" && chmod +x addvlgrpc
wget -O addvless "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addvless" && chmod +x addvless
#List ShadowSocks
wget -O addshadow "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addshadow" && chmod +x addshadow
wget -O addsso "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addsso" && chmod +x addsso
wget -O addssws "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addssws" && chmod +x addssws
wget -O addsshu "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addsshu" && chmod +x addsshu
wget -O addssgrpc "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addssgrpc" && chmod +x addssgrpc
#Additional
wget -O status "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/status" && chmod +x status
wget -O addtrial "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/addtrial" && chmod +x addtrial
wget -O menu "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/menu" && chmod +x menu
wget -O ceklogin "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/ceklogin" && chmod +x ceklogin
wget -O hapus "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/hapus" && chmod +x hapus
wget -O renew "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/renew" && chmod +x renew
wget -O resetusage "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/resetusage" && chmod +x resetusage
wget -O buat_token "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/buat_token" && chmod +x buat_token
wget -O cekservice "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/cekservice" && chmod +x cekservice
wget -O ram "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/ram" && chmod +x ram
wget -O menu-backup "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/menu-backup" && chmod +x menu-backup
wget -O menu-reboot "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/menu-reboot" && chmod +x menu-reboot
wget -O menu-akun "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/menu-akun" && chmod +x menu-akun
wget -O backup "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/backup" && chmod +x backup
wget -O clearlog "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/clearlog" && chmod +x clearlog
wget -O ceklog "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/ceklog" && chmod +x ceklog
wget -O cekerror "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/cekerror" && chmod +x cekerror
wget -O ceknginx "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/ceknginx" && chmod +x ceknginx
wget -O expired "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/expired" && chmod +x expired
wget -O setlimit "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/setlimit" && chmod +x setlimit
wget -O autokill "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/autokill" && chmod +x autokill
wget -O fix-ssl "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/fix-ssl.sh" && chmod +x fix-ssl
wget -O ganticore "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/ganticore" && chmod +x ganticore
cd

#Install reboot dan expired otomatis
wget -O /usr/bin/reboot_otomatis "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/reboot_otomatis.sh";
chmod +x /usr/bin/reboot_otomatis;
echo "00 1 * * * root /usr/bin/expired" >> /etc/cron.d/expired_otomatis;
systemctl restart cron;

#install Firewall
apt install ufw -y
apt install fail2ban -y
sudo echo -e "[sshd]\nbackend=systemd\nenabled=true" | sudo tee /etc/fail2ban/jail.local
systemctl restart fail2ban
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 1080/tcp
sudo ufw allow 2082/tcp
sudo ufw allow 2083/tcp
sudo ufw allow 3128/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 8880/tcp
sudo ufw allow 8081/tcp
sudo ufw allow $port/tcp
yes | sudo ufw enable
systemctl enable ufw
systemctl start ufw

#install database
wget -O /var/lib/marzban/db.sqlite3 "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/utilitas/db.sqlite3"

#install warp
wget -O /root/warp "https://raw.githubusercontent.com/cs-69/mpv/refs/heads/master/DOCS/command/install_warp_proxy.sh"
sudo chmod +x /root/warp
sudo bash /root/warp -y
rm /root/warp

#finishing
apt autoremove -y
apt clean
cd /opt/marzban
sed -i "s/# SUDO_USERNAME = \"admin\"/SUDO_USERNAME = \"${userpanel}\"/" /opt/marzban/.env
sed -i "s/# SUDO_PASSWORD = \"admin\"/SUDO_PASSWORD = \"${passpanel}\"/" /opt/marzban/.env
sed -i "s/UVICORN_PORT = 7879/UVICORN_PORT = ${port}/" /opt/marzban/.env
docker compose down && docker compose up -d
marzban cli admin import-from-env -y
sed -i "s/SUDO_USERNAME = \"${userpanel}\"/# SUDO_USERNAME = \"admin\"/" /opt/marzban/.env
sed -i "s/SUDO_PASSWORD = \"${passpanel}\"/# SUDO_PASSWORD = \"admin\"/" /opt/marzban/.env
docker compose down && docker compose up -d
cd
echo "Tunggu 30 detik untuk generate token API"
sleep 30s

#instal token
curl -X 'POST' \
  "https://${domain}:${port}/api/admin/token" \
  -H 'accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&username=${userpanel}&password=${passpanel}&scope=&client_id=&client_secret=" > /etc/data/token.json
cd
neofetch
sed -i '/info title/d' ~/.config/neofetch/config.conf
sed -i '/info "Packages" packages/d' ~/.config/neofetch/config.conf
sed -i '/info "Shell" shell/d' ~/.config/neofetch/config.conf
sed -i '/info "Resolution" resolution/d' ~/.config/neofetch/config.conf
sed -i '/info "Memory" memory/d' ~/.config/neofetch/config.conf
profile
echo "Untuk data login dashboard: " | tee -a log-install.txt
echo "-=================================-" | tee -a log-install.txt
echo "URL       : https://${domain}:${port}/dashboard" | tee -a log-install.txt
echo "username  : ${userpanel}" | tee -a log-install.txt
echo "password  : ${passpanel}" | tee -a log-install.txt
echo "-=================================-" | tee -a log-install.txt
echo "Jangan lupa untuk set pengaturan ini jika diperlukan:" | tee -a log-install.txt
echo -e "Sett limit Xray dengan perintah \e[1;32msetlimit\e[0m" | tee -a log-install.txt
echo "-=================================-" | tee -a log-install.txt
echo -e "Sett Backup telegram dengan perintah \e[1;32mmenu-backup\e[0m" | tee -a log-install.txt
echo "-=================================-" | tee -a log-install.txt
echo -e "Sett reboot otomatis server dengan perintah \e[1;32mmenu-reboot\e[0m" | tee -a log-install.txt
echo "-=================================-" | tee -a log-install.txt
echo "Script telah berhasil di install" | tee -a log-install.txt
rm /root/jebalui.sh
marzban cli admin delete -u admin -y
echo -e "[\e[1;31mWARNING\e[0m] Reboot sekali biar ga error lur [default y](y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
