#!/bin/bash

# Usage: ./1-reconRanger.sh reoft.com reoft
# Put reoft.com either in script folder or result folder otherwise it'll not save
# Arg 1: DomainList
# Arg 2: Folder Name
# scp recon.sh root@158.220.96.161:/root/readyalpha/scripts

# Initial
	printf "\033c"
	RED="\e[31m"
	GREEN="\e[32m"
	YELLOW="\033[0;33m"
	ENDCOLOR="\e[0m"

	domain_list=$1
	folder_name=$2
	mkdir -p ../result;

	if [ -d "../result/$2" ]; then
	    echo -e "${GREEN}[$(date "+%H:%M:%S")] ${ENDCOLOR}$2 directory already exists"
	    mkdir -p ../result/$2;
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")] ${ENDCOLOR}$2 Directory with name $2 created in result folder"
	    mkdir -p ../result/$2;
	fi
	dir=./../result/$2;
	
	if [ "$#" -ne 2 ]; then
	  echo -e "${RED}Script requires two arguments:
	  • domain_list    | eg. h1-domains.txt
	  • directory name | eg. hackerone
	  • Usage: ./recon.sh h1-domains.txt hackerone
	  • Supply even single domain in a file to avoid further multiple domain implementation${ENDCOLOR}"
	  exit 1
	fi

	# Banner
		echo -e "                                                                        "
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
		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Supply even single domain in a file"
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Keep updating Nuclei templates manually"
		var=$(cat $domain_list | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} You've provided $var domains for ${GREEN}$2${ENDCOLOR}"
		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}"

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
	if [ -e "/usr/bin/$tool" ]; then
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
	#nuclei_templates_move
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";	
}
tools_check

function subdomain_enumeration(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Recon Started"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting subdomains using Subfinder"
	subfinder -dL $domain_list -silent -o $dir/subdomains.txt >> /dev/null;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting subdomains using AssetFinder"
	for i in $(<$domain_list); do (echo $i | assetfinder -subs-only | anew -q $dir/subdomains.txt;); done;
	for i in $(<$domain_list); do (echo $i | anew -q $dir/subdomains.txt); done;
	httpx -l $dir/subdomains.txt -silent -o $dir/live-domains.txt >> /dev/null;

	# Cero
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding for more subdomains via SSL certs using Cero"
	cat $dir/live-domains.txt | sed 's/http[s]*:\/\///g' | cero -d -c 1000 | anew -q $dir/new-domains-by-cero.txt;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking live subdomains which are found via SSL certs using Cero"
	cat $dir/new-domains-by-cero.txt | httpx -silent | anew -q $dir/live-domains.txt;

	echo -e "${GREEN}\n[$(date "+%H:%M:%S")]${ENDCOLOR} Checking live hosts"
	var1=$(cat $dir/live-domains.txt | wc -l); var2=$(cat $dir/subdomains.txt | wc -l);
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var1 out of $var2 hosts are live & saved as \"live-domains.txt\""

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Saving all (active + inactive) domains as \"all-domains.txt\""
	cat $dir/subdomains.txt $dir/new-domains-by-cero.txt $dir/live-domains.txt | sed 's/http[s]*:\/\///g' | anew -q $dir/all-domains.txt;
	var3=$(cat $dir/all-domains.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var3 total (active + inactive) domains found"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} These will be used for port scanning to discover new attack surface"
	rm $dir/subdomains.txt $dir/new-domains-by-cero.txt;

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";

	# Final = $dir/live-domains.txt
}

function robots_txt(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting domains which contain ${GREEN}robots.txt${ENDCOLOR}";
	cat $dir/live-domains.txt | httpx -silent | sed 's#/$##;s#$#/robots.txt#' | anti-burl | awk '{print $4}' | anew -q $dir/robots.txt;
	var=$(cat $dir/live-domains.txt | wc -l); var2=$(cat $dir/robots.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var2 out of $var domains have 'robots.txt' file & saved as $2/robots.txt${ENDCOLOR}";
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
robots_txt

function endpoint_collection(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Crawling domains"
	cat $domain_list | httpx -silent | hakrawler -insecure -subs -t 20 -u >> $dir/crawled-urls.txt;
	var=$(cat $dir/crawled-urls.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var endpoints found and saved as ${GREEN}crawled-urls.txt${ENDCOLOR}";

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting Wayback data";
	cat $dir/live-domains.txt | waybackurls >> $dir/waybackdata.txt;
	var=$(cat $dir/waybackdata.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var endpoints found and saved as ${GREEN}waybackdata.txt${ENDCOLOR}";

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting Gau data"
	cat $dir/live-domains.txt | gau >> $dir/gau.txt;
	var=$(cat $dir/gau.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var endpoints found and saved as ${GREEN}gau.txt${ENDCOLOR}";

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging waybackurls & gau data for further crawling"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Also checking live endpoints"
	cat $dir/waybackdata.txt $dir/gau.txt | sort -u | anti-burl | awk '{print $4}' | anew -q $dir/waybackurls-gau-combined.txt;
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merged live URLs as ${GREEN}waybackurls-gau-combined.txt${ENDCOLOR}--> Now deleting waybackurls & gau files"
	rm $dir/waybackdata.txt $dir/gau.txt;
	echo -e "${GREEN}[$(date "+%H:%M:%S")] waybackdata.txt${ENDCOLOR} & ${GREEN}gau.txt${ENDCOLOR} deleted"

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Crawling archived urls"
	cat $dir/waybackurls-gau-combined.txt | hakrawler -insecure -subs -t 20 -u >> $dir/crawled-archived-urls.txt;
	var=$(cat $dir/crawled-archived-urls.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var endpoints found and saved as ${GREEN}crawled-archived-urls${ENDCOLOR}";

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Combining live URLs from waybackurls, gau, crawled domains & crawled archived urls text files";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take a bit longer";
	cat $dir/crawled-urls.txt $dir/waybackurls-gau-combined.txt $dir/crawled-archived-urls.txt | anti-burl | awk '{print $4}' | anew -q $dir/all-endpoints.txt;
	var=$(cat $dir/all-endpoints.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var endpoints found and saved as ${GREEN}all-endpoints.txt${ENDCOLOR}";

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Deleting waybackdata-gau-combined.txt, crawled-urls.txt & crawled-archived-urls.txt";
	rm $dir/crawled-urls.txt $dir/waybackurls-gau-combined.txt $dir/crawled-archived-urls.txt;

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Saving clean endpoints (^http.*)";
	cat $dir/all-endpoints.txt | grep -E "^(http|https)://.*" | anew -q $dir/endpoints.txt; rm $dir/all-endpoints.txt;

	var=$(cat $dir/endpoints.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var unique endpoints with (^http.*) found & saved as ${GREEN} $2/endpoints.txt${ENDCOLOR}";

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: $dir/endpoints.txt
}

function portscan(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} PortScanning in progress!"
	#echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take time as nmap is also detecting running services"
	for domain in $(<$dir/all-domains.txt); do (echo $domain | naabu -host $domain -passive -silent -scan-all-ips | anew -q $dir/openports.txt); done;
	var=$(cat $dir/openports.txt | wc -l); var2=$(cat $dir/all-domains.txt | wc -l);
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var ports are open for $var2 domains & saved as ${GREEN} $folder_name/openports.txt${ENDCOLOR}"
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";

	# Final: $dir/openports.txt
}
portscan

function domain_titles(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting domains + subdomains title"
	cat $dir/live-domains.txt | httpx -silent | ./get-title | anew -q $dir/domain-titles.txt;
	var=$(cat $dir/domain-titles.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var domains title grabbed & saved as $folder_name/domain-titles.txt${ENDCOLOR}"
	
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: domain-titles.txt
}
domain_titles

function endpoint_titles(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting endpoints title"
	if [ -e "$dir/endpoints.txt" ]; then
	cat $dir/endpoints.txt | ./get-title | anew -q $dir/endpoint-titles.txt;
	var=$(cat $dir/endpoint-titles.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] $var endpoints title grabbed & saved as $folder_name/endpoint-titles.txt ${ENDCOLOR}"
	else
	echo -e "${RED}[$(date "+%H:%M:%S")] No \"endpoints.txt\" file found, so skipping${ENDCOLOR}";
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
endpoint_titles

function open_ports_title(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Collecting open ports title"
	if [ -e "$dir/openports.txt" ]; then
	cat $dir/openports.txt | httpx -silent | ./get-title | anew -q $dir/open_ports_title.txt;
	var=$(cat $dir/open_ports_title.txt | wc -l)
	echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} $var titles grabbed for open ports domain & saved as $folder_name/open_ports_title.txt"
	else
	echo -e "${RED}[$(date "+%H:%M:%S")] No $folder_name/openports.txt file found, so skipping${ENDCOLOR}";
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: open_ports_title.txt
}
open_ports_title

function getjs(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading JS files";
	# If live-domains.txt & endpoints.txt exist
	if [ -e "$dir/live-domains.txt" ] && [ -e "$dir/endpoints.txt" ]; then
		
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} All files exist";
		# Execute the getJS command
		mkdir -p "$dir/getjs"
		cd "$dir/getjs"
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading all JS files in temp ${GREEN}getjs${ENDCOLOR} directory";
		cat "../../$dir/live-domains.txt" "../../$dir/endpoints.txt" | getJS | xargs wget -q
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging all JS in one as 1js.txt";
		cat * >> "../../$dir/1js.txt"
		cd ..
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Folder containing individual JS files i.e getjs deleted";
		rm -r ./getjs;

		if [ -s "1js.txt" ]; then
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Successfully merged all JS in one as ${GREEN}1js.txt${ENDCOLOR}";
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] Failed to merge all JS files${ENDCOLOR}";
			rm 1js.txt;
		fi

	elif [ -e "$dir/live-domains.txt" ] || [ -e "$dir/endpoints.txt" ]; then

		# Execute the getJS command for each available file
		mkdir -p "$dir/getjs"
		cd "$dir/getjs"

		if [ -e "../../$dir/live-domains.txt" ]; then
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Only ${GREEN}live-domains.txt${ENDCOLOR} found";
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading all JS files in temp getjs directory";
			cat "../../$dir/live-domains.txt" | getJS | xargs wget -q
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging all JS in one as 1js.txt";
			cat * >> "../../$dir/1js.txt"
			cd ..
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Folder containing individual JS files i.e getjs deleted";
			rm -r ./getjs

			if [ -s "1js.txt" ]; then
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Successfully merged all JS in one as ${GREEN}1js.txt${ENDCOLOR}";
			else
				echo -e "${YELLOW}[$(date "+%H:%M:%S")] Failed to merge all JS files${ENDCOLOR}";
				rm 1js.txt;
			fi


		elif [ -e "../../$dir/endpoints.txt" ]; then
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Only ${GREEN}endpoints.txt${ENDCOLOR} found";
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading all JS files in temp getjs directory";
			cat "../../$dir/endpoints.txt" | getJS | xargs wget -q
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Merging all JS in one as 1js.txt";
			cat * >> "../../$dir/1js.txt"
			cd ..
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Folder containing individual JS files i.e getjs deleted";
			rm -r ./getjs

			if [ -s "1js.txt" ]; then
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Successfully merged all JS in one as ${GREEN}1js.txt${ENDCOLOR}";
			else
				echo -e "${YELLOW}[$(date "+%H:%M:%S")] Failed to merge all JS files${ENDCOLOR}";
				rm 1js.txt;
			fi

		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] Something went wrong while downloading JS files${ENDCOLOR}";
		fi

	else
		# Print a message indicating that both files are missing
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Something went wrong either files does not exist or GetJS was not able to process domains correctl${ENDCOLOR}";
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Skipping JS files download${ENDCOLOR}";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: 1js.txt
}
getjs

function filefinder(){
	mkdir -p $dir/imp_files_list; imp_files_list="$dir/imp_files_list";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Extracting important files from endpoints.txt";

	#JS
	if [ $(cat $dir/endpoints.txt | grep '.*\.\(js\|mjs\|jsx\|ts\|vue\|coffee\|es6\|jsp\).*' | wc -l) -gt 0 ]; then
	    cat $dir/endpoints.txt | grep '.*\.\(js\|mjs\|jsx\|ts\|vue\|coffee\|es6\|jsp\).*' | anew -q $imp_files_list/JSfiles.txt
	    var=$(cat $imp_files_list/JSfiles.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var JS files found & saved to ${GREEN}$folder_name/imp_files_list/JSfiles.txt${ENDCOLOR}";
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No JS files found";
	fi
	#Final: JSfiles.txt

	#Sensitive
	if [ $(cat $dir/endpoints.txt | grep '.*\.\(back\|backup\|bak\|bakup\|conf\|mdb\|db\|doc\|ini\|rar\|source\|zip\|bac\|sql\|cache\|csproj\|err\|java\|log\|tar\|tar.gz\|tmp\|vb\|git\|xls\|cfg\|swp\|old\|php\|php5\|php7\|config\|cnf\|py\|action\|do\|docx\|yaml\|yml\|class\|md\|access_log\|allow\|bash_config\|bash_history\|bash_logout\|bashrc\|BeforeVMwareToolsInstall\|chroot_list\|conf-vesa\|conf-vmware\|crit\|default\|defs\|deny\|dpkg-old\|error_log\|htaccess\|httpd\|include\|info\|ksh_history\|legacy\|lighttpdpassword\|log1\|log2\|lst\|master\|new\|nmbd\|notice\|options\|orig\|out\|passwd\|pdb\|pl\|properties\|rules\|smb\|smbd\|user\|users\|warn\|Xauthority\|xferlog\).*' | wc -l) -gt 0 ]; then
	    cat $dir/endpoints.txt | grep '.*\.\(back\|backup\|bak\|bakup\|conf\|mdb\|db\|doc\|ini\|rar\|source\|zip\|bac\|sql\|cache\|csproj\|err\|java\|log\|tar\|tar.gz\|tmp\|vb\|git\|xls\|cfg\|swp\|old\|php\|php5\|php7\|config\|cnf\|py\|action\|do\|docx\|yaml\|yml\|class\|md\|access_log\|allow\|bash_config\|bash_history\|bash_logout\|bashrc\|BeforeVMwareToolsInstall\|chroot_list\|conf-vesa\|conf-vmware\|crit\|default\|defs\|deny\|dpkg-old\|error_log\|htaccess\|httpd\|include\|info\|ksh_history\|legacy\|lighttpdpassword\|log1\|log2\|lst\|master\|new\|nmbd\|notice\|options\|orig\|out\|passwd\|pdb\|pl\|properties\|rules\|smb\|smbd\|user\|users\|warn\|Xauthority\|xferlog\).*' | anew -q $imp_files_list/sensitivefiles.txt
	    var=$(cat $imp_files_list/sensitivefiles.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")]${ENDCOLOR} $var Sensitive files found & saved to ${GREEN}$folder_name/imp_files_list/sensitivefiles.txt${ENDCOLOR}";
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No Sensitive files found";
	fi
	#Final: sensitivefiles.txt
}
filefinder
