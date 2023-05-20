#!/bin/bash
# This script contains OWASP vulnerability assessment techniques

# Initials
	target=$1
	dir=./../result/$1;
	RED="\e[31m"
	GREEN="\e[32m"
	YELLOW="\033[0;33m"
	ENDCOLOR="\e[0m"

	# required arguments
	if [ "$#" -ne 1 ]; then
	  echo -e "${RED}Script requires 1 argument:
	  • directory name | eg. hackerone
	  • Usage: ./2-autoSeeker.sh hackerone${ENDCOLOR}"
	  exit 1
	fi

	# Target is available or not?
	if [ ! -d "$dir" ]; then
	  echo -e "${YELLOW}$target${ENDCOLOR}${RED} does not exist in result folder. (ls ../result)${ENDCOLOR}"
	  exit 1
	fi

	# Creating 4eliteSonic folder
	if [ ! -d "$dir/4eliteSonic" ]; then
		mkdir -p $dir/4eliteSonic;
	fi

	# Variables
	reconRanger=$dir/1reconRanger;
	output4=$dir/4eliteSonic;


	# live-domains exists
	if [ ! -s "$reconRanger/live-domains.txt" ]; then
	    echo -e "${RED}Error: 'live-domains.txt' does not exists in $target${ENDCOLOR}"
	    exit 1
	fi

	# endpoints exists
	if [ ! -s "$reconRanger/endpoints.txt" ]; then
	    echo -e "${RED}Error: 'endpoints.txt' does not exist or is empty in $target${ENDCOLOR}"
	    exit 1
	fi


	#count
	echo -e "\n${GREEN}-------------------------------------------------${ENDCOLOR}";
	domain_count=$(cat $reconRanger/live-domains.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Performing automated testing for ${GREEN}$target${ENDCOLOR}"
	endpoint_count=$(cat $reconRanger/endpoints.txt | wc -l);
	openport_count=$(cat $reconRanger/openports.txt | wc -l);
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";


function xss_1(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} XSS_1 - Basic test by replacing parameter value with XSS payload using QSReplace";


}

# Implement bypasses
# cpanelXSS
# expanded paths
# add parameters in every endpoints