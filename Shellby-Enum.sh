#!/bin/bash


echo "

                                                                         bbbbbbbb
   SSSSSSSSSSSSSSS hhhhhhh                                lllllll lllllllb::::::b
 SS:::::::::::::::Sh:::::h                                l:::::l l:::::lb::::::b
S:::::SSSSSS::::::Sh:::::h                                l:::::l l:::::lb::::::b
S:::::S     SSSSSSSh:::::h                                l:::::l l:::::l b:::::b
S:::::S             h::::h hhhhh           eeeeeeeeeeee    l::::l  l::::l b:::::bbbbbbbbb yyyyyyy           yyyyyyy
S:::::S             h::::hh:::::hhh      ee::::::::::::ee  l::::l  l::::l b::::::::::::::bby:::::y         y:::::y
 S::::SSSS          h::::::::::::::hh   e::::::eeeee:::::eel::::l  l::::l b::::::::::::::::by:::::y       y:::::y
  SS::::::SSSSS     h:::::::hhh::::::h e::::::e     e:::::el::::l  l::::l b:::::bbbbb:::::::by:::::y     y:::::y
    SSS::::::::SS   h::::::h   h::::::he:::::::eeeee::::::el::::l  l::::l b:::::b    b::::::b y:::::y   y:::::y
       SSSSSS::::S  h:::::h     h:::::he:::::::::::::::::e l::::l  l::::l b:::::b     b:::::b  y:::::y y:::::y
            S:::::S h:::::h     h:::::he::::::eeeeeeeeeee  l::::l  l::::l b:::::b     b:::::b   y:::::y:::::y
            S:::::S h:::::h     h:::::he:::::::e           l::::l  l::::l b:::::b     b:::::b    y:::::::::y
SSSSSSS     S:::::S h:::::h     h:::::he::::::::e         l::::::ll::::::lb:::::bbbbbb::::::b     y:::::::y
S::::::SSSSSS:::::S h:::::h     h:::::h e::::::::eeeeeeee l::::::ll::::::lb::::::::::::::::b       y:::::y
S:::::::::::::::SS  h:::::h     h:::::h  ee:::::::::::::e l::::::ll::::::lb:::::::::::::::b       y:::::y
 SSSSSSSSSSSSSSS    hhhhhhh     hhhhhhh    eeeeeeeeeeeeee llllllllllllllllbbbbbbbbbbbbbbbb       y:::::y
                                                                                                y:::::y
                                                                                               y:::::y
                                                                                              y:::::y
                                                                                             y:::::y
                                                                                            yyyyyyy
v0.1

"

help(){
  echo "
Usage: ./Scan.sh [options] -d domain.com
Options:
    -h            Display this help message.
    -n            Run Nmap on all subdomains found.
    -a            Run Arjun on all subdomains found.
    -p            Run Photon crawler on all subdomains found.
    -b            Run Custom Bruteforcer to find subdoamins.
    -e            Run amass after subfinder
    -k            Kill mode: Actively exploit all positive results (Can be illegal)
  Target:
    -d            Specify the domain to scan.

Example:
    ./Shellby.sh -d hackerone.com -n --killmode
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
if [ ! -d $PWD/Scan ]; then
        mkdir Scan
fi
if [ ! -d $PWD/Scan/$d ]; then
        mkdir Scan/$d
fi
source tokens.txt

echo "Starting our subdomain enumeration force..."

rm -rf Scan/$d/fourth-levels/ Scan/$d/*.txt Scan/$d/results/ Scan/$d/links/ Scan/$d/linkstemp/



TD="Scan/$d/fourth-levels/";
if [ ! -d "$TD" ]; then
    # If it doesn't create it
    mkdir $TD
fi

RES="Scan/$d/results/";
if [ ! -d "$RES" ]; then
    # If it doesn't create it
    mkdir $RES
fi

TL="Scan/$d/links/";
if [ ! -d "$TL" ]; then
    mkdir $TL
fi

LT="Scan/$d/linkstemp/"
if [ ! -d "$LT" ]; then
    mkdir $LT
fi

######### Begin Recon on all subdomains

echo "Starting Sublist3r..."
python3 ~/BugBounty/Tools/Sublist3r/sublist3r.py -d "$d" -o Scan/$d/fromsublister.txt

if [[ "$*" = *"-e"* ]]
then
echo "Amass turn..."
amass enum --passive -d $d -o Scan/$d/fromamass.txt
fi

echo "Starting subfinder..."
subfinder -d $d -o Scan/$d/fromsubfinder.txt -v --exclude-sources dnsdumpster

echo "Starting assetfinder..."
assetfinder --subs-only $d > Scan/$d/fromassetfinder.txt

rm -rf amass_output

echo "Starting github-subdomains..."
python3 github-subdomains.py -t $github_token_value -d $d | sort -u >> Scan/$d/fromgithub.txt

echo "Starting findomain"
export findomain_fb_token="$findomain_fb_token"
export findomain_spyse_token="$findomain_spyse_token"
export findomain_virustotal_token="$findomain_virustotal_token"

findomain -t $d -r -u Scan/$d/fromfindomain.txt

nl=$'\n'
echo "Starting bufferover"
curl "http://dns.bufferover.run/dns?q=$d" --silent | jq '.FDNS_A | .[]' -r 2>/dev/null | cut -f 2 -d',' | sort -u >> Scan/$d/frombufferover-dns.txt
echo "$nl"
echo "Bufferover DNS"
echo "$nl"
cat Scan/$d/frombufferover-dns.txt
curl "http://dns.bufferover.run/dns?q=$d" --silent | jq '.RDNS | .[]' -r 2>/dev/null | cut -f 2 -d',' | sort -u >> Scan/$d/frombufferover-dns-rdns.txt
echo "$nl"
echo "Bufferover DNS-RDNS"
echo "$nl"
cat Scan/$d/frombufferover-dns-rdns.txt
curl "http://tls.bufferover.run/dns?q=$d" --silent | jq '. | .Results | .[]'  -r 2>/dev/null | cut -f 3 -d ',' | sort -u >> Scan/$d/frombufferover-tls.txt
echo "$nl"
echo "Bufferover TLS"
echo "$nl"
cat Scan/$d/frombufferover-tls.txt

if [[ "$*" = *"-b"* ]]
then
  echo "Starting our custom bruteforcer"
  for sub in $(cat subdomains.txt); do echo $sub.$d >> /tmp/sub-$d.txt; done
  massdns -r ~/BugBounty/Tools/massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/subresolved-$d.txt /tmp/sub-$d.txt
  rm /tmp/sub-$d.txt
  awk -F ". " "{print \$d}" /tmp/subresolved-$d.txt | sort -u >> Scan/$d/fromcustbruter.txt
  rm /tmp/subresolved-$d.txt
fi
cat Scan/$d/*.txt | grep $d | grep -v '*' | sort -u | grep -Po "(\w+\.\w+\.\w+)$" >> Scan/$d/alltogether.txt

echo "Deleting other(older) results"
rm -rf Scan/$d/from*

echo "Resolving - Part 1"
massdns -r ~/BugBounty/Tools/massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/massresolved1.txt Scan/$d/alltogether.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> Scan/$d/resolved1.txt
rm /tmp/massresolved1.txt
rm Scan/$d/alltogether.txt

echo "Removing wildcards"
cat Scan/$d/resolved1.txt | grep -Po "(\w+\.$d)$" | httpx >> Scan/$d/resolved1-nowilds.txt
cat Scan/$d/resolved1.txt | grep -Po "(\w+\.\w+\.$d)$" | httpx >> Scan/$d/resolved1-nowilds.txt
rm Scan/$d/resolved1.txt

echo "Starting AltDNS..."
altdns -i Scan/$d/resolved1-nowilds.txt -o Scan/$d/fromaltdns.txt -t 300

echo "Resolving - Part 2 - Altdns results"
massdns -r ~/BugBounty/Tools/massdns/lists/resolvers.txt -s 1000 -q -o S -w /tmp/massresolved1.txt Scan/$d/fromaltdns.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> Scan/$d/altdns-resolved.txt
rm /tmp/massresolved1.txt
rm Scan/$d/fromaltdns.txt

echo "Removing wildcards - Part 2"
cat Scan/$d/altdns-resolved.txt | grep -Po "(\w+\.$d)$" | httpx >> Scan/$d/altdns-resolved-nowilds.txt
cat Scan/$d/altdns-resolved.txt | grep -Po "(\w+\.\w+\.$d)$" | httpx >> Scan/$d/altdns-resolved-nowilds.txt
rm Scan/$d/altdns-resolved.txt

cat Scan/$d/*.txt | sort -u >> Scan/$d/alltillnow.txt
rm Scan/$d/altdns-resolved-nowilds.txt
rm Scan/$d/resolved1-nowilds.txt

echo "Starting DNSGEN..."
dnsgen Scan/$d/alltillnow.txt >> Scan/$d/fromdnsgen.txt

echo "Resolving - Part 3 - DNSGEN results"
massdns -r ~/BugBounty/Tools/massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/massresolved1.txt Scan/$d/fromdnsgen.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> Scan/$d/dnsgen-resolved.txt
rm /tmp/massresolved1.txt
#rm /tmp/forbrut.txt
rm Scan/$d/fromdnsgen.txt

echo "Removing wildcards - Part 3"
cat Scan/$d/dnsgen-resolved.txt | grep -Po "(\w+\.$d)$" | httpx >> Scan/$d/dnsgen-resolved-nowilds.txt
cat Scan/$d/dnsgen-resolved.txt | grep -Po "(\w+\.\w+\.$d)$" | httpx >> Scan/$d/dnsgen-resolved-nowilds.txt
rm Scan/$d/dnsgen-resolved.txt

cat Scan/$d/alltillnow.txt | grep $d |  grep -Po "(\w+\.\w+\.\w+\.$d)$" | sed 's/http/ /g'| sed 's/https/ /g' | sort -u >> Scan/$d/$d.txt
cat Scan/$d/alltillnow.txt | grep $d |  grep -Po "(\w+\.\w+\.$d)$" | sed 's/http/ /g'| sed 's/https/ /g' | sort -u >> Scan/$d/$d.txt
cat Scan/$d/alltillnow.txt | grep $d |  grep -Po "(\w+\.$d)$" | sed 's/http/ /g'| sed 's/https/ /g' | sort -u >> Scan/$d/$d.txt
cat Scan/$d/$d.txt | sort -u > Scan/$d/$d2.txt
cat Scan/$d/$d2.txt > Scan/$d/$d.txt
rm Scan/$d/$d2.txt
rm Scan/$d/dnsgen-resolved-nowilds.txt
rm Scan/$d/alltillnow.txt

echo "Appending http/s to hosts"
awk '$0="https://"$0' Scan/$d/$d.txt  >> Scan/$d/with-protocol-domains.txt
cat Scan/$d/with-protocol-domains.txt | httpx | sort -u  >>  Scan/$d/alive.txt
echo "Taking screenshots..."
cat Scan/$d/alive.txt | aquatone -ports xlarge -out Scan/$d/aquascreenshots

if [[ "$*" = *"-a"* ]]
then
        python3 ~/BugBounty/Tools/Arjun/arjun.py --urls Scan/$d/alive.txt --get -o Scan/$d/arjun_out.txt -f ~/BugBounty/Tools/Arjun/db/params.txt
fi


echo "Total hosts found: $(wc -l Scan/$d/alive.txt)"

if [[ "$*" = *"-n"* ]]
then
        echo "Starting Nmap"
  if [ ! -d $PWD/Scan/$d/nmap ]; then
        mkdir Scan/$d/nmap
  fi
        for i in $(cat Scan/$d/alive.txt); do nmap -sC -sV $i -o Scan/$d/nmap/$i.txt; done
fi

if [[ "$*" = *"-p"* ]]
then
        echo "Starting Photon Crawler"
  if [ ! -d $PWD/Scan/$d/photon ]; then
        mkdir Scan/$d/photon
  fi
        for i in $(cat Scan/$d/alive.txt); do python3 ~/BugBounty/Tools/Photon/photon.py -u $i -o Scan/$d/photon/$i -l 2 -t 50; done
fi

echo "Checking for Subdomain Takeover"
python3 ~/BugBounty/Tools/subdomain-takeover/takeover.py -d $d -f Scan/$d/alive.txt -t 20  >>  Scan/$d/subdomain_takeover.txt

echo "Starting DirSearch"
if [ ! -d $PWD/Scan/$d/dirsearch ]; then
        mkdir Scan/$d/dirsearch
fi

for i in $(cat Scan/$d/alive.txt | sed 's/https\?:\/\///' | sed 's/http\?:\/\///');do ffuf -w  ~/BugBounty/Tools/dirsearch/db/dicc.txt -u https://$i/FUZZ  -timeout 3 -o Scan/$d/dirsearch/$i.txt -of md;done
#Runs Gospider on all picked up domains to find any links assosciated with them, cleans them up into URL's within our scope and moves them to the next step (EXPLOITATION!)
echo "Cleaning up URLS"
cat Scan/$d/dirsearch/* | gf urls | sed 's/:80//g' | sed 's/:433//g'   > Scan/$d/spiderlinks.txt
cat Scan/$d/alive.txt  >> Scan/$d/spiderlinks.txt
echo "Running Gospider on domains (Things start taking a while from this point onwards. Be patient.)"

gospider -S Scan/$d/spiderlinks.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)"  >>  Scan/$d/spiderlinks2.txt

cat Scan/$d/spiderlinks2.txt | gf urls | grep $d | qsreplace 'input' | sort -u  >> Scan/$d/spiderlinks.txt
rm Scan/$d/spiderlinks2.txt
echo "Done with the GoSpider scan!"
echo "Link crawling is now finished; find results in text file: spiderlinks.txt"

#Uses gf to find possible injection points. (GF Patterns can be independently modified and I recommend you do so, a lot of parameters can go unnoticed with many of the patterns on github)

echo "Making neat exploitation links with gf"
echo "generating links to exploit"
for patt in $(cat patterns); do gf $patt Scan/$d/spiderlinks.txt | qsreplace -a |  sort -u  >>  Scan/$d/linkstemp/$patt-links.txt;done
for patt in $(cat patterns); do cat Scan/$d/linkstemp/$patt-links.txt | gf $patt | qsreplace -a | grep -v js | sort -u | httpx | sort -u > Scan/$d/links/$patt-links.txt;done
rm -rf Scan/$d/linkstemp/

# Uses fimap to search for Local File Inclusion vulnerabilities
echo "Using fimap to scan for LFI vulns"
python2 ~/BugBounty/Tools/fimap/src/fimap.py -m -l Scan/$d/links/lfi-links.txt -w Scan/$d/results/lfi-results.txt
echo "fimap scan finished"
# Uses dalfox to exploit links found by crawling and waybackurls
echo "Started vulnerability scanning. Please maintain your patience"

echo "Running XSS scans on links.."

cat Scan/$d/links/xss-links.txt | kxss | gf urls | sort -u > Scan/$d/links/xss-links-valid.txt
cat Scan/$d/links/xss-links-valid.txt > Scan/$d/links/xss-links.txt
rm Scan/$d/links/xss-links-valid.txt

echo "Successfully reflected xss links can be found in Scan/$d/links/xss-links.txt"

#echo "Running SQLI scans on links"

#for sql in $(cat Scan/$d/links/sqli-links.txt); do python3 ~/BugBounty/Tools/DSSS/dsss.py -u $sql >> Scan/$d/links/sqli-links-valid.txt;done
#python2 ~/BugBounty/Tools/sqli-scanner/sqli-scanner.py -f Scan/$d/links/sqli-links.txt -o Scan/$d/links/sqli-links-valid.txt
#cat Scan/$d/links/sqli-links-valid.txt > Scan/$d/links/sqli-links.txt
#rm Scan/$d/links/sqli-links-valid.txt

clear

echo "Scan finished, these are the results"
echo "Find all results in Scan/$d/links/"
echo ""
echo ""
echo "Possible XSS Vulnerabilities:"
cat Scan/$d/links/xss-links.txt | wc -l
#echo ""
#echo ""
#echo "Possible SQLI vulnerabilities"
#cat Scan/$d/links/sqli-links.txt | wc -l
echo ""
echo ""
echo "Possible LFI Vulnerabilities"
cat Scan/$d/results/lfi-results.txt | wc -l

echo "Exploitatin has begun"
echo ""
cat Scan/$d/links/xss-links.txt | dalfox pipe  >>  Scan/$d/results/xss-results.txt



#Uses the perfectly crafted SQLMAP to find vulnerabilities in HTTP headers, PHP cookies and the provided input (Overall 10/10 tool)
#echo "Running SQL Injections on links"
#sqlmap -m Scan/$d/links/sqli-links.txt --batch --level 2  | tee Scan/$d/results/sqli-results.txt


#echo "Cleaning up files!"

#echo "Exploiting links with nuclei templates..."
#nuclei -t ~/BugBounty/Tools/nuclei-templates/ -l spiderlinks.txt -o Scan/$d/results/$d-nuclei-results.txt

#echo "Checking for valid waybackurls"
#Runs Waybackurls to find old links (Some of them are no longer visible on google, some lucky break might occur)
#echo "Running Waybackmachine on all successfully probed domain names"
#awk '$0="https://"$0' probed.txt | waybackurls | grep $d | qsreplace -a 'input' | sort -u  >> waybackurls.txt
#echo "Waybackmachine search finished."

#httpx -l waybackurls.txt > spiderlinks.txt
#echo "Notifying you on slack"
#curl -X POST -H 'Content-type: application/json' --data '{"text":"Scan finished scanning: '$d'"' $slack_url
