#!/bin/bash

# Usage: ./1-reconRanger.sh reoft.com reoft
# Put reoft.com either in script folder or result folder otherwise it'll not save
# Arg 1: DomainList
# Arg 2: Folder Name
# scp recon.sh root@158.220.96.161:/root/readyalpha/scripts

# Initial
	RED="\e[31m"
	GREEN="\e[32m"
	YELLOW="\033[0;33m"
	ENDCOLOR="\e[0m"


	domain_list=$1
	folder_name=$2
	mkdir -p ../result;


	# Banner
		echo -e "                                                                          "
		echo -e "                    .&&   &&&&&                                           "
		echo -e "                &&&&  &&&&&,                                              "
		echo -e "           &&&&&&&&&&&&&&&                                                "
		echo -e "     &&&&&&&&&&&&&&%%%%&,                                           /&&&&&"
		echo -e "  ,&&&&&&&&&&&&%%&%%%%%     .&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  "
		echo -e "  &&&&&&&&&%%%&&&&&&&&    %&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&    "
		echo -e "            /%&&&&&&&    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(       "
		echo -e "           &&&&&&&&.    &&&&&&&&                                          "
		echo -e "          &&&&&&&&    ,&&&&&&&&     &&&&&&&&&&&&&&&&&&&&&&&&&&&&&#        "
		echo -e "         &&&&&&&&    &&&&&&&&     &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&          "
		echo -e "       #&&&&&&&%    &&&&&&&&     &&&&&&&&&&&&&&&&&&&&&&&&&&&&             "
		echo -e "      (&&&&&&&     &&&&&&&&    %&&&&&&&,                                  "
		echo -e "      &&&&&&&    (%&&&&&&&    &&&&&&&&    ((((((((((((((((                "
		echo -e "     (&&&&&&&   &%&&&&&&%    &&&&&&&&  &&&&&&&&&&&&&&&&&                  "
		echo -e "     /&&&&%&&  &&%&&&&&*    &&&&&&&&&&&&&&&&&&&&&&&&&                     "
		echo -e "      &&&&&&&%%%&&&&&&    .&&&&&&&                                        "
		echo -e "       &&&&&&&&&&&&&&    &&&&&&&                                          "
		echo -e "         &&&&&&&&&&&    &&&&       ${GREEN}PROJECT ALPHA${ENDCOLOR}       "
		echo -e "           &&%&&&&&                 ${GREEN}-by 0xKaran${ENDCOLOR}        "
		echo -e "            &&&&&&&                                                       "
		echo -e "            &&&&&&&&                                                      "
		echo -e "             &&&&&&&&&&          &&&&&                                    "
		echo -e "               &&&&&&&&&&&&&&&&&&&&(                                      "
		echo -e "                  &&&&&&&&&&&&&&                                          "
		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
		echo -e "${GREEN}Features:${ENDCOLOR} Subdomain Enum | Robots.txt | URLs | JS | Titles";
		echo -e "${GREEN}Features:${ENDCOLOR} PortsScan | File/Config/Param finder | Path expand";
		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Supply even single domain in a file"
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Keep updating Nuclei templates manually"
		
		var=$(cat $domain_list | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} You've provided $var domains for ${GREEN}$2${ENDCOLOR}"
		if [ -d "../result/$2" ]; then
		    echo -e "${GREEN}[$(date "+%H:%M:%S")] ${ENDCOLOR}$2 directory already exists"
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")] ${ENDCOLOR}$2 Directory with name $2 created in result folder"
		  mkdir -p ../result/$2;
		fi

		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}"

		dir=./../result/$2;
		output1=$dir/1reconRanger
		mkdir -p $dir/1reconRanger
	
	if [ "$#" -ne 2 ]; then
	  echo -e "${RED}Script requires two arguments:
	  • domain_list    | eg. h1-domains.txt
	  • directory name | eg. hackerone
	  • Usage: ./recon.sh h1-domains.txt hackerone
	  • Supply even single domain in a file to avoid further multiple domain implementation${ENDCOLOR}"
	  exit 1
	fi

function tools_check(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking for required tools"	
		TOOLS=(
		httprobe
		anew
		katana
		meg
		subfinder
		getJS
		assetfinder
		httpx
		waybackrobots
		ffuf
		qsreplace
		subzy
		hakrawler
		gau
		concurl
		nuclei
		cero
		waybackurls
		burl
		unfurl
	)

	for tool in "${TOOLS[@]}"; do
	if [ -e "/usr/bin/$tool" ] || [ -e "/usr/local/bin/$tool" ]; then
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $tool installed"
	else
	echo -e "${RED}[$(date "+%H:%M:%S")] $tool not installed! Exiting${ENDCOLOR}"
	exit 1
	fi
	done

	# Anti-burl installation check
	if [ -e "./anti-burl" ]; then
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Anti-Burl installed";
	else
	echo -e "${RED}[$(date "+%H:%M:%S")] Anti-Burl not installed! Exiting${ENDCOLOR}";
	exit 1
	fi

	if [ -f "./testssl/testssl.sh" ]; then
	  echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} TestSSL installed"
	else
	echo -e "${RED}[$(date "+%H:%M:%S")] TestSSL not installed! Exiting${ENDCOLOR}";
	exit 1
	fi

	# Sprawl-----------------------------------------------------------
    if [ -e "./sprawl.py" ] && [ -s "./sprawl.py" ]; then
      echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Sprawl installed";
    else
      echo -e "${RED}[$(date "+%H:%M:%S")] Either Sprawl does not exist or the file is empty${ENDCOLOR}";
      echo -e "${RED}[$(date "+%H:%M:%S")] For more info: https://github.com/tehryanx/sprawl${ENDCOLOR}";
      exit 1
    fi

	function nuclei_templates_move(){
	    nuclei -update-templates -silent
	    # Check if the destination directory already exists
	    if test -d "./nuclei-templates"; then
	        # Check if the directory is empty
	        if test -z "$(ls -A ./nuclei-templates)"; then
	            # Move the ~/nuclei-templates directory to the current directory
	            rmdir ./nuclei-templates
	            mv ~/nuclei-templates ./nuclei-templates

	            # Check if the move command succeeded
	            if [ $? -eq 0 ]; then
	              echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Nuclei-template directory already exists but empty so moved successfully";
	            else
	                echo -e "${RED}[$(date "+%H:%M:%S")] Nuclei-template directory move failed${ENDCOLOR}";
	                exit 1
	            fi
	        else

	            echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Nuclei-template directory already exists and is not empty";
	            echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Check if it contains nuclei-templates or not while tool is busy in other thing";
	        fi
	    else
	        # Move the ~/nuclei-templates directory to the current directory
	        mv ~/nuclei-templates .

	        # Check if the move command succeeded
	        if [ $? -eq 0 ]; then
	          echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Nuclei-template directory moved successfully";
	        else
	            echo -e "${RED}[$(date "+%H:%M:%S")] Nuclei-template directory move failed${ENDCOLOR}";
	            exit 1
	        fi
	    fi


	    var=$(pwd)
	    export NUCLEI_TEMPLATES_PATH=$var/nuclei-templates
	    if [ "$NUCLEI_TEMPLATES_PATH" = "$var/nuclei-templates" ] && [ -d "nuclei-templates" ]; then
	        echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} NUCLEI_TEMPLATES_PATH is set correctly to \"$NUCLEI_TEMPLATES_PATH\""
	    else
	        echo -e "${RED}[$(date "+%H:%M:%S")] NUCLEI_TEMPLATES_PATH is not set correctly or \"nuclei-templates\" folder does not exists${ENDCOLOR}";
	        echo -e "${RED}[$(date "+%H:%M:%S")] If \"nuclei-templates\" not installed, run ${YELLOW}\$ nuclei -update-templates${ENDCOLOR}";
	        echo -e "${RED}[$(date "+%H:%M:%S")] See \"requirements.sh\" for fix${ENDCOLOR}";
	        exit 1
	    fi
	}
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";	
}
tools_check

function subdomain_enumeration(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Recon Started"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting subdomains using Subfinder"
	subfinder -dL $domain_list -silent -o $dir/1reconRanger/subdomains.txt >> /dev/null;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting subdomains using AssetFinder"
	for i in $(<$domain_list); do (echo $i | assetfinder -subs-only | anew -q $dir/1reconRanger/subdomains.txt;); done;
	for i in $(<$domain_list); do (echo $i | anew -q $dir/1reconRanger/subdomains.txt); done;
	httpx -l $dir/1reconRanger/subdomains.txt -silent -o $dir/1reconRanger/live-domains.txt >> /dev/null;

	# Cero
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding more subdomains via SSL certs using Cero"
	cat $dir/1reconRanger/live-domains.txt | sed 's/http[s]*:\/\///g' | cero -d -c 1000 | anew -q $dir/1reconRanger/new-domains-by-cero.txt;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking live subdomains which are found via SSL certs using Cero"
	cat $dir/1reconRanger/new-domains-by-cero.txt | httpx -silent | anew -q $dir/1reconRanger/live-domains.txt;

	echo -e "${GREEN}\n[$(date "+%H:%M:%S")]${ENDCOLOR} Checking live hosts"
	var1=$(cat $dir/1reconRanger/live-domains.txt | wc -l); var2=$(cat $dir/1reconRanger/subdomains.txt | wc -l);
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var1 out of $var2 hosts are live & saved as > $folder_name/1reconRanger/live-domains.txt"

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Saving all (active + inactive) domains as > all-domains.txt"
	cat $dir/1reconRanger/subdomains.txt $dir/1reconRanger/new-domains-by-cero.txt $dir/1reconRanger/live-domains.txt | sed 's/http[s]*:\/\///g' | anew -q $dir/1reconRanger/all-domains.txt;
	var3=$(cat $dir/1reconRanger/all-domains.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Stored total $var3 (active + inactive) domains"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} These will be used for port scanning to discover new attack surface"
	rm $dir/1reconRanger/subdomains.txt $dir/1reconRanger/new-domains-by-cero.txt;

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";

	# Final = $dir/1reconRanger/live-domains.txt
}
subdomain_enumeration

function robots_txt(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding robots.txt";
	cat $dir/1reconRanger/live-domains.txt | httpx -silent | sed 's#/$##;s#$#/robots.txt#' | anti-burl | awk '{print $4}' | anew -q $dir/1reconRanger/robots.txt;

	# File is empty or not
	if [ -e $dir/1reconRanger/robots.txt ]; then

		if [ -s $dir/1reconRanger/robots.txt ]; then
			var=$(cat $dir/1reconRanger/live-domains.txt | wc -l); var2=$(cat $dir/1reconRanger/robots.txt | wc -l)
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var2 out of $var domains have 'robots.txt' file & saved as > $folder_name/1reconRanger/robots.txt${ENDCOLOR}";
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No 'robots.txt' found";
			rm $dir/1reconRanger/robots.txt;
		fi

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Unable to create 'robots.txt' file in $folder_name"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
robots_txt

function endpoint_collection(){

	# Domain Crawl-------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Crawling domains"
	cat $domain_list | httpx -silent | hakrawler -insecure -subs -t 20 -u >> $dir/1reconRanger/crawled-urls.txt;
	# File is empty or not
	if [ -e $dir/1reconRanger/crawled-urls.txt ]; then
		if [ -s $dir/1reconRanger/crawled-urls.txt ]; then
			var=$(cat $dir/1reconRanger/crawled-urls.txt | wc -l);
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var links found from crawling domains & saved as > $folder_name/1reconRanger/crawled-urls.txt";
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No link found from crawling";
			rm $dir/1reconRanger/crawled-urls.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Unable to create 'crawled-urls.txt' file in $folder_name"
	fi

	# WaybackURLs----------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting Wayback data";
	cat $dir/1reconRanger/live-domains.txt | waybackurls >> $dir/1reconRanger/waybackdata.txt;

	# File is empty or not
	if [ -e $dir/1reconRanger/waybackdata.txt ]; then
		if [ -s $dir/1reconRanger/waybackdata.txt ]; then
			var2=$(cat $dir/1reconRanger/waybackdata.txt | wc -l);
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var2 endpoints found from waybackurls & saved as > $folder_name/1reconRanger/waybackdata.txt";
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No endpoints found from waybackurls";
			rm $dir/1reconRanger/waybackdata.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Unable to create 'waybackdata.txt' file in $folder_name"
	fi

	# Gau-------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting Gau data"
	cat $dir/1reconRanger/live-domains.txt | gau >> $dir/1reconRanger/gau.txt;

	# File is empty or not
	if [ -e $dir/1reconRanger/gau.txt ]; then
		if [ -s $dir/1reconRanger/gau.txt ]; then
			var3=$(cat $dir/1reconRanger/gau.txt | wc -l);
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var3 endpoints found from Gau & saved as > $folder_name/1reconRanger/gau.txt";
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] No endpoint found from Gau${ENDCOLOR}";
			rm $dir/1reconRanger/gau.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Unable to create 'gau.txt' file in $folder_name"
	fi

	# Merge-------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging waybackurls & gau data for further crawling"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Also checking live endpoints"
	cat $dir/1reconRanger/waybackdata.txt $dir/1reconRanger/gau.txt 2>/dev/null | anti-burl | awk '{print $4}' | anew -q $dir/1reconRanger/waybackurls-gau-combined.txt;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merged live URLs as waybackurls-gau-combined.txt"
	cat $dir/1reconRanger/waybackdata.txt $dir/1reconRanger/gau.txt | anew -q $dir/1reconRanger/all-endpoints.txt;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} waybackdata.txt & gau.txt combined as all-endpoints.txt"
	rm $dir/1reconRanger/waybackdata.txt $dir/1reconRanger/gau.txt;

	# Archived crawl----------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Crawling live archived urls"
	cat $dir/1reconRanger/waybackurls-gau-combined.txt | hakrawler -insecure -subs -t 20 -u >> $dir/1reconRanger/crawled-archived-urls.txt;

	# File is empty or not
	if [ -e $dir/1reconRanger/crawled-archived-urls.txt ]; then
		if [ -s $dir/1reconRanger/crawled-archived-urls.txt ]; then
			var4=$(cat $dir/1reconRanger/crawled-archived-urls.txt | wc -l);
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var4 links found from crawling archived urls & saved as > $folder_name/1reconRanger/crawled-archived-urls.txt";
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No link found from crawling archived urls";
			rm $dir/1reconRanger/crawled-archived-urls.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Unable to crawl live archived urls"
	fi

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Combining live URLs from waybackurls, gau, crawled domains & crawled archived urls text files";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take a bit longer";
	cat $dir/1reconRanger/crawled-urls.txt $dir/1reconRanger/waybackurls-gau-combined.txt $dir/1reconRanger/crawled-archived-urls.txt | anti-burl | awk '{print $4}' | anew -q $dir/1reconRanger/all-endpoints.txt;

	# File is empty or not
	if [ -e $dir/1reconRanger/all-endpoints.txt ]; then
		if [ -s $dir/1reconRanger/all-endpoints.txt ]; then
			var5=$(cat $dir/1reconRanger/all-endpoints.txt | wc -l);
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var5 links combined total & saved as > $folder_name/1reconRanger/all-endpoints.txt";
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Deleting ${GREEN}waybackdata-gau-combined.txt, crawled-urls.txt & crawled-archived-urls.txt${ENDCOLOR}";
			rm $dir/1reconRanger/crawled-urls.txt $dir/1reconRanger/waybackurls-gau-combined.txt $dir/1reconRanger/crawled-archived-urls.txt;
			
				# Finalising endpoints.txt
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Saving clean endpoints (${GREEN}^http[s]?://.*${ENDCOLOR})";
				cat $dir/1reconRanger/all-endpoints.txt | grep -E "^(http|https)://.*" | anew -q $dir/1reconRanger/endpoints.txt;
				# File is empty or not
				if [ -e $dir/1reconRanger/endpoints.txt ]; then
					if [ -s $dir/1reconRanger/endpoints.txt ]; then
						var6=$(cat $dir/1reconRanger/endpoints.txt | wc -l);
						echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var6 final endpoints found & saved as > $folder_name/1reconRanger/endpoints.txt";
					else
						echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} 0 endpoint found with ^http[s]";
						echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} verify at $dir/1reconRanger/all-endpoints.txt";
					fi
				else
					echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error saving clean endpoints"
				fi

		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} all-endpoints.txt is empty, hence deleted";
			rm $dir/1reconRanger/all-endpoints.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Unable to combine waybackdata, gau, crawled urls & domains";
	fi

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} all-endpoints.txt all urls from wayback, gau, crawl, archive crawl";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This can be used to extract paths & parameters";


	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: $dir/1reconRanger/endpoints.txt
}
endpoint_collection

function portscan(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} PortScanning in progress!"
	#echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take time as nmap is also detecting running services"
	for domain in $(<$dir/1reconRanger/all-domains.txt); do (echo $domain | naabu -host $domain -passive -silent -scan-all-ips | anew -q $dir/1reconRanger/openports.txt); done;
	var=$(cat $dir/1reconRanger/openports.txt | wc -l); var2=$(cat $dir/1reconRanger/all-domains.txt | wc -l);
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var ports are open for $var2 domains & saved as > $folder_name/1reconRanger/openports.txt${ENDCOLOR}"
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";

	# Final: $dir/1reconRanger/openports.txt
}
portscan

function critical_ports(){
	# Read the file containing the list of domains and ports
	while IFS= read -r line; do
	    # Use grep to match the regex patterns
	    if echo "$line" | grep -qE ':445$'; then
	        echo -e "${YELLOW}[$(date "+%H:%M:%S")] SMB port 445 open at : $line${ENDCOLOR}";
	        echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null
	        echo -e "${YELLOW}           Check for possible attack vectors at 1.3 of https://t.ly/oJCMl${ENDCOLOR}";
	        echo -e "${YELLOW}           Eg: bruteforcing credentials ${ENDCOLOR}"
	    elif echo "$line" | grep -qE ':21$'; then
	        echo -e "${YELLOW}[$(date "+%H:%M:%S")] FTP port 21 open at : $line${ENDCOLOR}";
	        echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null
	        echo -e "${YELLOW}           Check for possible attack vectors at 1.3 of https://t.ly/oJCMl${ENDCOLOR}";
	        echo -e "${YELLOW}           Eg: anonymous login or bruteforcing credentials ${ENDCOLOR}"
	    elif echo "$line" | grep -qE ':22$'; then
	        echo -e "${YELLOW}[$(date "+%H:%M:%S")] SSH port 22 open at : $line${ENDCOLOR}";
	        echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null
	        echo -e "${YELLOW}           Check for possible attack vectors at 1.3 of https://t.ly/oJCMl${ENDCOLOR}";
	        echo -e "${YELLOW}           Eg: bruteforcing credentials ${ENDCOLOR}"
	    elif echo "$line" | grep -qE ':1433$'; then
	        echo -e "${YELLOW}[$(date "+%H:%M:%S")] MSSQL port 1433 open at : $line${ENDCOLOR}";
	        echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null
	        echo -e "${YELLOW}           Check for possible attack vectors at 1.3 of https://t.ly/oJCMl${ENDCOLOR}";
	        echo -e "${YELLOW}           Eg: anonymous login or bruteforcing credentials${ENDCOLOR}"
			elif echo "$line" | grep -qE ':23$'; then
				  echo -e "${YELLOW}[$(date "+%H:%M:%S")] Telnet port 23 open at : $line${ENDCOLOR}";
				  echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null
				   echo -e "${YELLOW}           Check for unencrypted telnet server${ENDCOLOR}";
			elif echo "$line" | grep -qE ':25$'; then
				  echo -e "${YELLOW}[$(date "+%H:%M:%S")] SMPT port 23 open at : $line${ENDCOLOR}";
				  echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null;
				  echo -e "${YELLOW}           Eg: bruteforcing credentials ${ENDCOLOR}"
	    elif echo "$line" | grep -qE ':3306$'; then
	        echo -e "${YELLOW}[$(date "+%H:%M:%S")] MySQL port 1433 open at : $line${ENDCOLOR}";
	        echo "$line" | anew "$dir/1reconRanger/critical_ports.txt" > /dev/null
	    fi
	done < $dir/1reconRanger/openports.txt

	if [ -e "$dir/1reconRanger/critical_ports.txt" ]; then
  	  count=$(cat "$dir/1reconRanger/critical_ports.txt" | wc -l)
  	if ((count >= 1)); then
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] $count critical ports found & saved as > $folder_name/1reconRanger/critical_ports.txt${ENDCOLOR}"
			echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
		fi
	fi


	#Final: critical_ports.txt
}
critical_ports

function open_ports_title(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting open ports title"
	if [ -e "$dir/1reconRanger/openports.txt" ]; then
	cat $dir/1reconRanger/openports.txt | httpx -silent | ./get-title | anew -q $dir/1reconRanger/open_ports_title.txt;
	var=$(cat $dir/1reconRanger/open_ports_title.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var titles grabbed for open ports domain & saved as $folder_name/1reconRanger/open_ports_title.txt${ENDCOLOR}"
	else
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No $folder_name/openports.txt file found, so skipping${ENDCOLOR}";
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: open_ports_title.txt
}
open_ports_title

function domain_titles(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting (sub)?domain[s]? title"
	cat $dir/1reconRanger/live-domains.txt | httpx -silent | ./get-title | anew -q $dir/1reconRanger/domain-titles.txt;
	var=$(cat $dir/1reconRanger/domain-titles.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var domains title grabbed & saved as > $folder_name/1reconRanger/domain-titles.txt${ENDCOLOR}"
	
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: domain-titles.txt
}
domain_titles

function endpoint_titles(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting endpoints title"
	if [ -e "$dir/1reconRanger/endpoints.txt" ]; then
	cat $dir/1reconRanger/endpoints.txt | ./get-title | anew -q $dir/1reconRanger/endpoint-titles.txt;
	var=$(cat $dir/1reconRanger/endpoint-titles.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var endpoints title grabbed & saved as > $folder_name/1reconRanger/endpoint-titles.txt ${ENDCOLOR}"
	else
	echo -e "${RED}[$(date "+%H:%M:%S")] No \"endpoints.txt\" file found, so skipping${ENDCOLOR}";
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
endpoint_titles

function getjs(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading JS files from domains and endpoints";
	# If live-domains.txt & endpoints.txt exist
	if [ -s "$dir/1reconRanger/live-domains.txt" ] && [ -s "$dir/1reconRanger/endpoints.txt" ]; then
		
		# Execute the getJS command
		mkdir -p "$dir/1reconRanger/getjs"
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading all JS files in temp getjs directory";
		cat "$dir/1reconRanger/live-domains.txt" "$dir/1reconRanger/endpoints.txt" | getJS | xargs wget -q -P $dir/1reconRanger/getjs
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging all JS in one as 1js.txt";
		cat $dir/1reconRanger/getjs/* >> "$dir/1reconRanger/1js.txt"
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Folder containing individual JS files i.e ${GREEN}getjs${ENDCOLOR} deleted";
		rm -r $dir/1reconRanger/getjs;

		if [ -s "$dir/1reconRanger/1js.txt" ]; then
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Successfully merged all JS in one as ${GREEN}1js.txt${ENDCOLOR}";
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] Failed to merge all JS files${ENDCOLOR}";
			if [ -e $dir/1reconRanger/1js.txt ]; then
				rm $dir/1reconRanger/1js.txt;
			fi
		fi

	elif [ -s "$dir/1reconRanger/live-domains.txt" ] || [ -s "$dir/1reconRanger/endpoints.txt" ]; then

		# Execute the getJS command for each available file
		mkdir -p "$dir/1reconRanger/getjs"

		if [ -s "$dir/1reconRanger/live-domains.txt" ]; then
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Only live-domains.txt found";
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading all JS files in temp getjs directory from live-domains";
			cat "$dir/1reconRanger/live-domains.txt" | getJS | xargs wget -q -P $dir/1reconRanger/getjs
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging all JS in one as 1js.txt";
			cat $dir/1reconRanger/getjs/* >> "$dir/1reconRanger/1js.txt"
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Folder containing individual JS files i.e getjs deleted";
		  rm -r $dir/1reconRanger/getjs;

			if [ -s "$dir/1reconRanger/1js.txt" ]; then
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Successfully merged all JS in one as ${GREEN}1js.txt${ENDCOLOR}";
			else
				echo -e "${YELLOW}[$(date "+%H:%M:%S")] Failed to merge all JS files${ENDCOLOR}";
				if [ -e $dir/1reconRanger/1js.txt ]; then
					rm $dir/1reconRanger/1js.txt;
				fi
			fi


		elif [ -s "$dir/1reconRanger/endpoints.txt" ]; then
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Only endpoints.txt found";
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading all JS files in temp getjs directory from endpoints";
			cat "$dir/1reconRanger/endpoints.txt" | getJS | xargs wget -q -P $dir/1reconRanger/getjs
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging all JS in one as 1js.txt";
			cat $dir/1reconRanger/getjs/* >> "$dir/1reconRanger/1js.txt"
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Folder containing individual JS files i.e getjs deleted";
		  rm -r $dir/1reconRanger/getjs;

			if [ -s "$dir/1reconRanger/1js.txt" ]; then
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Successfully merged all JS in one as ${GREEN}1js.txt${ENDCOLOR}";
			else
				echo -e "${YELLOW}[$(date "+%H:%M:%S")] Failed to merge all JS files${ENDCOLOR}";
				if [ -e $dir/1reconRanger/1js.txt ]; then
					rm $dir/1reconRanger/1js.txt;
				fi
			fi

		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] Something went wrong while downloading JS files${ENDCOLOR}";
		fi

	else
		# Print a message indicating that both files are missing
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Something went wrong either files does not exist or GetJS was not able to process domains correct${ENDCOLOR}";
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Skipping JS files download${ENDCOLOR}";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: 1js.txt
}
getjs

function filefinder(){
	mkdir -p $dir/1reconRanger/imp_files_list; imp_files_list="$dir/1reconRanger/imp_files_list";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Extracting important files from endpoints.txt";

	if [ -e $dir/1reconRanger/endpoints.txt ]; then
		if [ -s $dir/1reconRanger/endpoints.txt ]; then
			#JS
			if [ $(cat $dir/1reconRanger/endpoints.txt | grep '.*\.\(js\|mjs\|jsx\|ts\|vue\|coffee\|es6\|jsp\).*' | wc -l) -gt 0 ]; then
			    cat $dir/1reconRanger/endpoints.txt | grep '.*\.\(js\|mjs\|jsx\|ts\|vue\|coffee\|es6\|jsp\).*' | anew -q $imp_files_list/JSfiles.txt
			    var=$(cat $imp_files_list/JSfiles.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var JS files found & saved to ${GREEN}$folder_name/imp_files_list/JSfiles.txt${ENDCOLOR}";
			fi

			#Sensitive
			if [ $(cat $dir/1reconRanger/endpoints.txt | grep '.*\.\(back\|backup\|bak\|bakup\|conf\|mdb\|db\|doc\|ini\|rar\|source\|zip\|bac\|sql\|cache\|csproj\|err\|java\|log\|tar\|tar.gz\|tmp\|vb\|git\|xls\|cfg\|swp\|old\|php\|php5\|php7\|config\|cnf\|py\|action\|do\|docx\|yaml\|yml\|class\|md\|access_log\|allow\|bash_config\|bash_history\|bash_logout\|bashrc\|BeforeVMwareToolsInstall\|chroot_list\|conf-vesa\|conf-vmware\|crit\|default\|defs\|deny\|dpkg-old\|error_log\|htaccess\|httpd\|include\|info\|ksh_history\|legacy\|lighttpdpassword\|log1\|log2\|lst\|master\|new\|nmbd\|notice\|options\|orig\|out\|passwd\|pdb\|pl\|properties\|rules\|smb\|smbd\|user\|users\|warn\|Xauthority\|xferlog\).*' | wc -l) -gt 0 ]; then
			    cat $dir/1reconRanger/endpoints.txt | grep '.*\.\(back\|backup\|bak\|bakup\|conf\|mdb\|db\|doc\|ini\|rar\|source\|zip\|bac\|sql\|cache\|csproj\|err\|java\|log\|tar\|tar.gz\|tmp\|vb\|git\|xls\|cfg\|swp\|old\|php\|php5\|php7\|config\|cnf\|py\|action\|do\|docx\|yaml\|yml\|class\|md\|access_log\|allow\|bash_config\|bash_history\|bash_logout\|bashrc\|BeforeVMwareToolsInstall\|chroot_list\|conf-vesa\|conf-vmware\|crit\|default\|defs\|deny\|dpkg-old\|error_log\|htaccess\|httpd\|include\|info\|ksh_history\|legacy\|lighttpdpassword\|log1\|log2\|lst\|master\|new\|nmbd\|notice\|options\|orig\|out\|passwd\|pdb\|pl\|properties\|rules\|smb\|smbd\|user\|users\|warn\|Xauthority\|xferlog\).*' | anew -q $imp_files_list/sensitivefiles.txt
			    var=$(cat $imp_files_list/sensitivefiles.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")]${ENDCOLOR} $var Sensitive files found & saved to ${GREEN}$folder_name/imp_files_list/sensitivefiles.txt${ENDCOLOR}";
			fi
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] 'endpoints.txt' is empty hence deleting ${ENDCOLOR}";
			rm $dir/1reconRanger/endpoints.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'endpoints.txt' found in $folder_name ${ENDCOLOR}";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: sensitivefiles.txt, JSfiles.txt
}
filefinder

function expand_paths(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Expanding URLs paths";
	if [ -e "$dir/1reconRanger/endpoints.txt" ] && [ -s "$dir/1reconRanger/endpoints.txt" ] ; then
		var=$(cat $dir/1reconRanger/endpoints.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var URLs found in endpoints.txt";
		for url in $(<$dir/1reconRanger/endpoints.txt); do (echo $url | ./sprawl.py | grep -vE '^(|\.)$' | anew -q $dir/1reconRanger/expanded_paths.txt); done
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Either 'endpoints.txt' is missing or the file is empty${ENDCOLOR}";
	fi

	if [ -e "$dir/1reconRanger/all-endpoints.txt" ] && [ -s "$dir/1reconRanger/all-endpoints.txt" ] ; then
		var2=$(cat $dir/1reconRanger/all-endpoints.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var2 URLs found in all-endpoints.txt";
		for url in $(<$dir/1reconRanger/all-endpoints.txt); do (echo $url | ./sprawl.py | grep -vE '^(|\.)$' | anew -q $dir/1reconRanger/expanded_paths.txt); done
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Either 'endpoints.txt' is missing or the file is empty${ENDCOLOR}";
	fi

	var3=$(cat $dir/1reconRanger/expanded_paths.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Expanded into $var3 paths > $folder_name/expanded_paths.txt";

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: expanded_paths.txt
}
expand_paths

function parameters(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Extracting parameters from endpoints.txt";

	if [ -e $dir/1reconRanger/endpoints.txt ] && [ -s $dir/1reconRanger/endpoints.txt ]; then

		cat $dir/1reconRanger/endpoints.txt | unfurl keys | anew -q $dir/1reconRanger/parameters.txt;
		if [ -e $dir/1reconRanger/parameters.txt ]; then
			if [ -s $dir/1reconRanger/parameters.txt ]; then
				param_count=$(cat $dir/1reconRanger/parameters.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $param_count parameters extracted from endpoints & saved as > $folder_name/1reconRanger/parameters.txt";
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No parameter found in endpoints";
				rm $dir/1reconRanger/parameters.txt
			fi
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No parameter found in endpoints";
		fi

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'endpoints.txt' found in $folder_name ${ENDCOLOR}";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: parameters.txt
}
parameters

function more_domains(){
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Discovering new domains using CSP";
		csprecon -l $output1/live-domains.txt -s | sed 's/\/.*//g' | sed 's/^\*\.//g' | anew -q $output1/more_domains.txt;

		# Check if found or not
		if [ -e $output1/more_domains.txt ]; then

			if [ -s $output1/more_domains.txt ]; then
				count=$(cat $output1/more_domains.txt | wc -l);
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $count new associated domains found for $folder_name & Saved as > $folder_name/1reconRanger/more_domains.txt";
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} These can be used for second order STO or finding new bugs or bruteforcing files/directories if everything is in scope!";
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No new domain found using CSP";
				rm $output1/more_domains.txt;
			fi

		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error discovering domains, Unable to create file";
		fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: more_domains.txt
}
more_domains

function reflected_parameters(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} FINDING REFLECTED PARAMETERS FOR XSS";
	cat $output1/endpoints.txt | qsreplace abcd1234 | reflector | anew -q $output1/reflected.txt;

	if [ -e $output1/reflected.txt ]; then
		if [ -s $output1/reflected.txt ]; then
			count=$(cat $output1/reflected.txt | wc -l);
			if [ $count -gt 0 ] ; then
				echo -e "${GREEN}[$(date "+%H:%M:%S")] $count reflected parameters found & Saved as > $folder_name/1reconRanger/reflected.txt ${ENDCOLOR}";
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No reflected parameters found";
				rm $output1/reflected.txt;
			fi
		else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No reflected parameters found";
				rm $output1/reflected.txt;
		fi
	else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No reflected parameters found";
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: reflected.txt
}
reflected_parameters

function zone_transfer(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} CHECKING FOR MISCONFIGURED DNS ZONE TRANSFER ON ALL DOMAINS!";
	
	# Loop through each domain in the list and check for zone transfer issues
	while IFS= read -r domain; do
	  echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking $domain"
	  dnsrecon -t axfr -d "$domain" >> "$dir/1reconRanger/zone_transfer.txt"
	done < "$dir/1reconRanger/all-domains.txt"

	# Checking if anything found
	count=$(grep -c "Zone Transfer was successful" "$dir/1reconRanger/zone_transfer.txt")
	if ((count >= 1)); then
		echo -e "${RED}[$(date "+%H:%M:%S")] $count nameservers have misconfigured DNS zone transfer & saved as > $folder_name/1reconRanger/zone_transfer.txt${ENDCOLOR}"
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No misconfigured zone transfer domain found"
		rm $dir/1reconRanger/zone_transfer.txt;
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: reflected.txt
}
zone_transfer
