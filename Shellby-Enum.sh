#!/bin/bash

### RECON SCRIPT MODIFIED AND ADOPTED FROM ECHOPWN SO I WILL KEEP THE CREDIT HERE



echo "
 _____     _           ____
| ____|___| |__   ___ |  _ \__      ___ __
|  _| / __| '_ \ / _ \| |_) \ \ /\ / / '_ \\
| |__| (__| | | | (_) |  __/ \ V  V /| | | |
|_____\___|_| |_|\___/|_|     \_/\_/ |_| |_|v1.1

"

help(){
  echo "
Usage: ./Scans.sh [options] -d domain.com
Options:
    -h            Display this help message.
    -k            Run Knockpy on the domain.
    -n            Run Nmap on all subdomains found.
    -a            Run Arjun on all subdomains found.
    -p            Run Photon crawler on all subdomains found.
    -b            Run Custom Bruteforcer to find subdoamins.

  Target:
    -d            Specify the domain to scan.

Example:
    ./Scans.sh -d hackerone.com
"
}

#### Setting up all the necessary folders ####


POSITIONAL=()

if [[ "$*" != *"-d"* ]]
then
        help
  exit
fi

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -h|--help)
    help
    exit
    ;;
    -d|--domain)
    d="$2"
    shift
    shift
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

echo "Starting SubEnum $d"

echo "Creating directory"
set -e
if [ ! -d $PWD/Scans ]; then
        mkdir Scans
fi
if [ ! -d $PWD/Scans/$d ]; then
        mkdir Scans/$d
fi
source tokens.txt

echo "Starting our subdomain enumeration force..."


if [[ "$*" = *"-k"* ]]
then
        echo "Starting KnockPy"
        mkdir Scans/$d/knock
        cd Scans/$d/knock; python3 ~/BugBounty/Tools/knockpy/knockpy.py "$d" -j; cd ../../..
fi

rm -rf Scans/$d/fourth-levels/ Scans/$d/*.txt Scans/$d/results/ Scans/$d/links/ Scans/$d/linkstemp/



TD="Scans/$d/fourth-levels/";
if [ ! -d "$TD" ]; then
    # If it doesn't create it
    mkdir $TD
fi

RES="Scans/$d/results/";
if [ ! -d "$RES" ]; then
    # If it doesn't create it
    mkdir $RES
fi

TL="Scans/$d/links/";
if [ ! -d "$TL" ]; then
    mkdir $TL
fi

LT="Scans/$d/linkstemp/"
if [ ! -d "$LT" ]; then
    mkdir $LT
fi

######### BEGIN ECHOPWN ENUM

echo "Starting Sublist3r..."
python3 Sublist3r/sublist3r.py -d "$d" -o Scans/$d/fromsublister.txt

echo "Amass turn..."
amass enum --passive -d $d -o Scans/$d/fromamass.txt

echo "Starting subfinder..."
subfinder -d $d -o Scans/$d/fromsubfinder.txt -v --exclude-sources dnsdumpster

echo "Starting assetfinder..."
assetfinder --subs-only $d > Scans/$d/fromassetfinder.txt

rm -rf amass_output

echo "Starting github-subdomains..."
python3 github-subdomains.py -t $github_token_value -d $d | sort -u >> Scans/$d/fromgithub.txt

echo "Starting findomain"
export findomain_fb_token="$findomain_fb_token"
export findomain_spyse_token="$findomain_spyse_token"
export findomain_virustotal_token="$findomain_virustotal_token"

findomain -t $d -r -u Scans/$d/fromfindomain.txt

nl=$'\n'
echo "Starting bufferover"
curl "http://dns.bufferover.run/dns?q=$d" --silent | jq '.FDNS_A | .[]' -r 2>/dev/null | cut -f 2 -d',' | sort -u >> Scans/$d/frombufferover-dns.txt
echo "$nl"
echo "Bufferover DNS"
echo "$nl"
cat Scans/$d/frombufferover-dns.txt
curl "http://dns.bufferover.run/dns?q=$d" --silent | jq '.RDNS | .[]' -r 2>/dev/null | cut -f 2 -d',' | sort -u >> Scans/$d/frombufferover-dns-rdns.txt
echo "$nl"
echo "Bufferover DNS-RDNS"
echo "$nl"
cat Scans/$d/frombufferover-dns-rdns.txt
curl "http://tls.bufferover.run/dns?q=$d" --silent | jq '. | .Results | .[]'  -r 2>/dev/null | cut -f 3 -d ',' | sort -u >> Scans/$d/frombufferover-tls.txt
echo "$nl"
echo "Bufferover TLS"
echo "$nl"
cat Scans/$d/frombufferover-tls.txt

if [[ "$*" = *"-b"* ]]
then
  echo "Starting our custom bruteforcer"
  for sub in $(cat subdomains.txt); do echo $sub.$d >> /tmp/sub-$d.txt; done
  massdns -r massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/subresolved-$d.txt /tmp/sub-$d.txt
  rm /tmp/sub-$d.txt
  awk -F ". " "{print \$d}" /tmp/subresolved-$d.txt | sort -u >> Scans/$d/fromcustbruter.txt
  rm /tmp/subresolved-$d.txt
fi
cat Scans/$d/*.txt | grep $d | grep -v '*' | sort -u | grep -Po "(\w+\.\w+\.\w+)$" >> Scans/$d/alltogether.txt

echo "Deleting other(older) results"
rm -rf Scans/$d/from*

echo "Resolving - Part 1"
massdns -r massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/massresolved1.txt Scans/$d/alltogether.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> Scans/$d/resolved1.txt
rm /tmp/massresolved1.txt
rm Scans/$d/alltogether.txt

echo "Removing wildcards"
cat Scans/$d/resolved1.txt | grep -Po "(\w+\.$d)$" | httpx >> Scans/$d/resolved1-nowilds.txt
cat Scans/$d/resolved1.txt | grep -Po "(\w+\.\w+\.$d)$" | httpx >> Scans/$d/resolved1-nowilds.txt
rm Scans/$d/resolved1.txt

echo "Starting AltDNS..."
altdns -i Scans/$d/resolved1-nowilds.txt -o Scans/$d/fromaltdns.txt -t 300

echo "Resolving - Part 2 - Altdns results"
massdns -r massdns/lists/resolvers.txt -s 1000 -q -o S -w /tmp/massresolved1.txt Scans/$d/fromaltdns.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> Scans/$d/altdns-resolved.txt
rm /tmp/massresolved1.txt
rm Scans/$d/fromaltdns.txt

echo "Removing wildcards - Part 2"
cat Scans/$d/altdns-resolved.txt | grep -Po "(\w+\.$d)$" | httpx >> Scans/$d/altdns-resolved-nowilds.txt
cat Scans/$d/altdns-resolved.txt | grep -Po "(\w+\.\w+\.$d)$" | httpx >> Scans/$d/altdns-resolved-nowilds.txt
rm Scans/$d/altdns-resolved.txt

cat Scans/$d/*.txt | sort -u >> Scans/$d/alltillnow.txt
rm Scans/$d/altdns-resolved-nowilds.txt
rm Scans/$d/resolved1-nowilds.txt

echo "Starting DNSGEN..."
dnsgen Scans/$d/alltillnow.txt >> Scans/$d/fromdnsgen.txt

echo "Resolving - Part 3 - DNSGEN results"
massdns -r massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/massresolved1.txt Scans/$d/fromdnsgen.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> Scans/$d/dnsgen-resolved.txt
rm /tmp/massresolved1.txt
#rm /tmp/forbrut.txt
rm Scans/$d/fromdnsgen.txt

echo "Removing wildcards - Part 3"
cat Scans/$d/dnsgen-resolved.txt | grep -Po "(\w+\.$d)$" | httpx >> Scans/$d/dnsgen-resolved-nowilds.txt
cat Scans/$d/dnsgen-resolved.txt | grep -Po "(\w+\.\w+\.$d)$" | httpx >> Scans/$d/dnsgen-resolved-nowilds.txt
rm Scans/$d/dnsgen-resolved.txt

cat Scans/$d/alltillnow.txt | grep $d |  grep -Po "(\w+\.\w+\.\w+\.\w+)$" | sed 's/http/ /g'| sed 's/https/ /g' | sort -u >> Scans/$d/$d.txt
cat Scans/$d/alltillnow.txt | grep $d |  grep -Po "(\w+\.\w+\.\w+)$" | sed 's/http/ /g'| sed 's/https/ /g' | sort -u >> Scans/$d/$d.txt
cat Scans/$d/$d.txt | sort -u > Scans/$d/$d2.txt
cat Scans/$d/$d2.txt > Scans/$d/$d.txt
rm Scans/$d/$d2.txt
rm Scans/$d/dnsgen-resolved-nowilds.txt
rm Scans/$d/alltillnow.txt

echo "Appending http/s to hosts"
awk '$0="https://"$0' Scans/$d/$d.txt  >> Scans/$d/with-protocol-domains.txt
cat Scans/$d/with-protocol-domains.txt | httpx | sort -u  >>  Scans/$d/alive.txt
echo "Taking screenshots..."
cat Scans/$d/alive.txt | aquatone -ports xlarge -out Scans/$d/aquascreenshots

if [[ "$*" = *"-a"* ]]
then
        python3 ~/BugBounty/Tools/Arjun/arjun.py --urls Scans/$d/alive.txt --get -o Scans/$d/arjun_out.txt -f Arjun/db/params.txt
fi


echo "Total hosts found: $(wc -l Scans/$d/alive.txt)"

if [[ "$*" = *"-n"* ]]
then
        echo "Starting Nmap"
  if [ ! -d $PWD/Scans/$d/nmap ]; then
        mkdir Scans/$d/nmap
  fi
        for i in $(cat Scans/$d/alive.txt); do nmap -sC -sV $i -o Scans/$d/nmap/$i.txt; done
fi

if [[ "$*" = *"-p"* ]]
then
        echo "Starting Photon Crawler"
  if [ ! -d $PWD/Scans/$d/photon ]; then
        mkdir Scans/$d/photon
  fi
        for i in $(cat Scans/$d/alive.txt); do python3 ~/BugBounty/Tools/Photon/photon.py -u $i -o Scans/$d/photon/$i -l 2 -t 50; done
fi

echo "Checking for Subdomain Takeover"
python3 ~/BugBounty/Tools/subdomain-takeover/takeover.py -d $d -f Scans/$d/alive.txt -t 20  >>  Scans/$d/subdomain_takeover.txt

echo "Starting DirSearch"
if [ ! -d $PWD/Scans/$d/dirsearch ]; then
        mkdir Scans/$d/dirsearch
fi

for i in $(cat Scans/$d/alive.txt | sed 's/https\?:\/\///' | sed 's/http\?:\/\///'); do ffuf -x php,asp,aspx,jsp,html,zip,jar  -w dirsearch/db/dicc.txt  -u https://$i/FUZZ -o "Scans/$d/dirsearch/$i-results.txt"; done







## EXPLOITATION - Entirely Coded by IsaacTheBrave






#Runs Gospider on all picked up domains to find any links assosciated with them, cleans them up into URL's within our scope and moves them to the next step (EXPLOITATION!)
echo "Cleaning up URLS"
cat Scans/$d/dirsearch/* | grep -E '2**|3**|5**' | gf urls | sed 's/:80//g' | sed 's/:433//g'   > Scans/$d/spiderlinks.txt
cat Scans/$d/alive.txt  >> Scans/$d/spiderlinks.txt
echo "Running Gospider on domains (Things start taking a while from this point onwards. Be patient.)"

gospider -S Scans/$d/spiderlinks.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)"  >>  Scans/$d/spiderlinks2.txt

cat Scans/$d/spiderlinks2.txt | gf urls | grep $d | qsreplace 'input' | sort -u  >> Scans/$d/spiderlinks.txt
rm Scans/$d/spiderlinks2.txt
echo "Done with the GoSpider scan!"
echo "Link crawling is now finished; find results in text file: spiderlinks.txt"

#Uses gf to find possible injection points. (GF Patterns can be independently modified and I recommend you do so, a lot of parameters can go unnoticed with many of the patterns on github)

echo "Making neat exploitation links with gf"
echo "generating links to exploit"
for patt in $(cat patterns); do gf $patt Scans/$d/spiderlinks.txt | grep $d | qsreplace -a |  sort -u  >>  Scans/$d/linkstemp/$patt-links.txt;done
for patt in $(cat patterns); do cat Scans/$d/linkstemp/$patt-links.txt | gf $patt | qsreplace -a | grep -v js | sort -u | httpx > Scans/$d/links/$patt-links.txt;done
rm -rf Scans/$d/linkstemp/

# Uses fimap to search for Local File Inclusion vulnerabilities
echo "Using fimap to scan for LFI vulns"
python2 ~/BugBounty/Tools/fimap/src/fimap.py -m -l Scans/$d/links/lfi-links.txt -w results/lfi-results.txt
echo "fimap scan finished"
# Uses dalfox to exploit links found by crawling and waybackurls
echo "Started vulnerability scanning. Please maintain your patience"

echo "Running XSS scans on links.."

cat Scans/$d/links/xss-links.txt | kxss | dalfox pipe  >>  Scans/$d/results/xss-results.txt

#Uses the perfectly crafted SQLMAP to find vulnerabilities in HTTP headers, PHP cookies and the provided input (Overall 10/10 tool)
echo "Running SQL Injections on links"
sqlmap -m Scans/$d/links/sqli-links.txt --batch --level 2  >>  Scans/$d/results/sqli-results.txt


echo "Cleaning up files!"

echo "Exploiting links with nuclei templates..."
#nuclei -t nuclei-templates/ -l spiderlinks.txt -o results/nuclei-results.txt

echo "Checking for valid waybackurls"
#Runs Waybackurls to find old links (Some of them are no longer visible on google, some lucky break might occur)
#echo "Running Waybackmachine on all successfully probed domain names"
#awk '$0="https://"$0' probed.txt | waybackurls | grep $d | qsreplace -a 'input' | sort -u  >> waybackurls.txt
#echo "Waybackmachine search finished."

#httpx -l waybackurls.txt > spiderlinks.txt
#echo "Notifying you on slack"
#curl -X POST -H 'Content-type: application/json' --data '{"text":"Scans finished scanning: '$d'"}' $slack_url

echo "Finished successfully."
