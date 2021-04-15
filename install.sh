#!/bin/bash

# This script is supposed to help install all the necessary tools to run an automated scan of a domain.

echo "updating and upgrading"
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
sudo apt-get update -y
sudo apt-get upgrade -y
sudo add-apt-repository universe
sudo apt-get update -y
clear
# Install necessary official packages
echo "installing necessary official packages"

sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y jq
sudo apt-get install -y ruby-full
sudo apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-get install -y python-setuptools
sudo apt-get install -y libldns-dev
sudo apt-get install -y python3-pip
sudo apt-get install -y python-pip
sudo apt-get install -y python-dnspython
sudo apt-get install -y git
sudo apt-get install -y rename
sudo apt-get install -y xargs
sudo apt-get install -y golang
sudo apt-get install -y python-dnspython
sudo apt-get install -y python2
sudo apt-get install -y nmap 
sudo apt-get install -y google-chrome-stable
sudo snap install amass
clear
echo "Installing Python2 pip"
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py | sudo python2
pip3 install -r requirements.txt
# Ready directories for downloads

echo "Making Directories for downloads"

mkdir ~/BugBounty
mkdir ~/BugBounty/Tools

# Start downloading and installin tools
# hakrawler - https://github.com/hakluke/hakrawler
echo "installing hakrawler"
go get github.com/hakluke/hakrawler
echo "hakrawler installed"

# ffuf - https://github.com/ffuf/ffuf
echo "installing ffuf" 

go get -u github.com/ffuf/ffuf

echo "ffuf installed"

# httprobe -https://github.com/tomnomnom/httprobe
echo "installing httprobe"

go get -u github.com/tomnomnom/httprobe

echo "httprobe installed"

# httpx - https://github.com/projectdiscovery/httpx
echo "installing httpx"

GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx

echo "httpx installed"

# Gospider - https://github.com/jaeles-project/gospider
echo "installing Gospider"

go get -u github.com/jaeles-project/gospider

echo "Gospider installed"

# Waybackurls - https://github.com/tomnomnom/waybackurls
echo "installing waybackurls"

go get -u github.com/tomnomnom/waybackurls

echo "waybackurls installed"
# Nuclei - https://github.com/projectdiscovery/nuclei
echo "installing nuclei"

GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

echo "Nuclei installed"

# Qsreplace - https://github.com/tomnomnom/qsreplace
echo "installing qsreplace"

go get -u github.com/tomnomnom/qsreplace

echo "qsreplace installed"

# kxss - https://github.com/tomnomnom/hacks/tree/master/kxss
echo "installing kxss"

cd ~/go/bin/
wget https://raw.githubusercontent.com/tomnomnom/hacks/master/kxss/main.go
go build main.go
rm main.go
mv main kxss
echo "kxss installed"

# dsss - https://github.com/stamparm/DSSS
echo "installing DSSS"
cd ~/BugBounty/Tools/
git clone https://github.com/stamparm/DSSS
cd ~ 
echo "DSSS installed"

# LFImap - https://github.com/kurobeats/fimap
echo "Installing fimap" 
cd ~/BugBounty/Tools/
git clone https://github.com/kurobeats/fimap.git
pip2 install httplib2
cd ~
echo "Installed fimap"

# Sublist3r - https://github.com/aboul3la/Sublist3r
echo "installing Sublist3r" 
cd ~/BugBounty/Tools/
git clone https://github.com/aboul3la/Sublist3r
cd Sublist3r
pip3 install -r requirements
git clone https://github.com/rthalley/dnspython
cd dnspython
sudo python3 setup.py install
cd ~
# Dalfox - https://github.com/hahwul/dalfox
echo "Installing dalfox"

GO111MODULE=on go get -v github.com/hahwul/dalfox/v2

echo "dalfox installed"

# Blind XSS - https://xsshunter.com
# Requires registration (best to replace this with something more mobile)

#GF-Patterns https://github.com/tomnomnom/gf
echo "Installing gf patterns"
go get -u github.com/tomnomnom/gf
cd ~
mkdir .gf
cd .gf
git clone https://github.com/Isaac-The-Brave/GF-Patterns-Redux
mv GF-Patterns-Redux/*.json .
rm -rf GF-Patterns-Redux
echo "Installed gf patterns"
clear

#Install assetfinder
echo "Installing assetfinder"
go get -u github.com/tomnomnom/assetfinder
echo "Installed assetfinder"

#Subfinder
echo "Installing subfinder"
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder 
echo "Installed subfinder"
sudo mv ~/go/bin/* /bin/

echo "Installing Some More tools"
cd ~/BugBounty

echo "Installing knockpy"
git clone https://github.com/guelfoweb/knock.git
cd knock
pip3 -r requirements.txt
#dirsearch
git clone https://github.com/maurosoria/dirsearch.git

#subdomain-takeover
git clone https://github.com/antichown/subdomain-takeover.git

#Photon
git clone https://github.com/s0md3v/Photon.git

#Findomain

wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
sudo mv findomain-linux /bin/findomain

#Nuclei Templates
echo "Installing nuclei-templates"
cd ~/BugBounty/Tools/
git clone https://github.com/projectdiscovery/nuclei-templates.git
echo "nuclei templates installed"


#Acquatone
echo "Installing aquatone"
cd ~/BugBounty/Tools
mkdir aquatone
cd aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone /bin/
echo "Installed aquatone"


cd ~/BugBounty/Tools
echo "Installing MassDNS"
git clone https://github.com/blechschmidt/massdns.git
cd massdns; make; cd ..
sudo mv massdns/bin/massdns /bin/
sed -i 's/from Queue/from queue/g' ~/.local/lib/python3.8/site-packages/altdns/__main__.py

echo "Installation finished. Please check ~/BugBounty and ~/Auto-Enum for future reference"
