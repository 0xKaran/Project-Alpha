#!/bin/bash

# Intermediet && Time consumer
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
	  • Usage: ./3-karnaCrusader.sh hackerone${ENDCOLOR}"
	  exit 1
	fi

	# Target is available or not?
	if [ ! -d "$dir" ]; then
	  echo -e "${YELLOW}$target${ENDCOLOR}${RED} does not exist in result folder. (ls ../result)${ENDCOLOR}"
	  exit 1
	fi

	# Creating 3karnaCrusader folder
	if [ ! -d "$dir/3karnaCrusader" ]; then
		mkdir -p $dir/3karnaCrusader;
	fi

	# Variables
	reconRanger=$dir/1reconRanger;
	autoSeeker=$dir/2autoSeeker;
	output3=$dir/3karnaCrusader;


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
	domain_count=$(cat $reconRanger/live-domains.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Performing time consuming testing using 3-karnaCrusader for ${GREEN}$target${ENDCOLOR}"
	endpoint_count=$(cat $reconRanger/endpoints.txt | wc -l);
	openport_count=$(cat $reconRanger/openports.txt | wc -l);
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";

# Open redirect is incomplete
function open_redirecx(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding open/unvalidated redirect in endpoints"
	# grep -E '\?[a-zA-Z0-9_]+=([a-zA-Z0-9_%]*)' $dir/endpoints.txt | while read i;
	# do url=$(echo "$i" | qsreplace FUZZ);
	# python3 OpenRedireX/openredirex.py -u "$url" -p OpenRedireX/payloads.txt --keyword FUZZ >> $dir/open_redirecx.txt; done;

	# count=$(cat $dir/open_redirecx.txt | grep -- " --> " | wc -l);

	# Set the input file path
	input_file="$dir/open_redirecx.txt"

	# Get the matching domains before and after " --> "
	domains_before=$(grep -oP '(?<=http[s]?:\/\/)[^\/]*(?=\/)' $input_file)
	domains_after=$(grep -oP '(?<= --> )[^\[\]]*(?=\[)')

	# extract domains before and after the " --> " delimiter
	grep -oE '[^ ]+\.[^ ]+ --> [^ ]+\.[^ ]+' input.txt | awk -F ' --> ' '{print $1 "\n" $2}' | sort | uniq -c | sort -rn



	# Count the number of matching domains
	count_before=$(echo "$domains_before" | sort -u | wc -l)
	count_after=$(echo "$domains_after" | sort -u | wc -l)

	# Print the results
	echo "Number of matching domains before --> : $count_before"
	echo "Number of matching domains after --> : $count_after"
}

# This is time consuming function, need to be separated
function host_header_injection(){

	# Time estimates
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding host header injection on endpoints with headi"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This tool does not support domains"
	if (( $(echo "($endpoint_count*15/60)-($endpoint_count*25/60)<1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Less than 3 mins remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $(expr $endpoint_count \* 15 / 60)-$(expr $endpoint_count \* 25 / 60) minutes remaining"; fi

	
	# Test
	for url in $(<$dir/endpoints.txt);
	do headi -u $url -t 5000 | anew -q $dir/host_header_injection_unfiltered.txt;
	done;


	# Extraction of possible vulnerable urls
	cat $dir/host_header_injection_unfiltered.txt | grep "[+]" | anew -q $dir/host_header_injection.txt;
	rm $dir/host_header_injection_unfiltered.txt


	# Counting how many found
	if [ -e $dir/host_header_injection.txt ]; then
		if [ -s $dir/host_header_injection.txt ]; then
			count=$(cat $dir/host_header_injection.txt | wc -l);
			echo -e "${RED}[$(date "+%H:%M:%S")] $count endpoints seem to be host header injection vulnerable${ENDCOLOR}"
			echo -e "${RED}[$(date "+%H:%M:%S")] But have high chances of false positive because tool relies on Content-Length change${ENDCOLOR}"
			echo -e "${RED}[$(date "+%H:%M:%S")] Manual check needed${ENDCOLOR}"
			python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$count endpoints seem to be host header injection vulnerable\n\nBut have high chances of false positive because tool relies on Content-Length change\n\nManual check needed\n\nFile saved as > $target/host_header_injection.txt")"
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No host header injection vulnerability found"
			rm $dir/host_header_injection.txt
		fi
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No host header injection vulnerability found"
	fi


	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: host_header_injection.txt
}

function exposedfiles(){


	# Add 2-aS/more_domains.txt


	echo -e "${GREEN}\n[$(date "+%H:%M:%S")]${ENDCOLOR} Hunting for exposed files/folders"
	mkdir -p $dir/exposedfiles

	if [ -e "./discoverylist.txt" ]; then
		wordlist="./discoverylist.txt"
		for domain in $(<$dir/live-domains.txt); do (ffuf -w $wordlist -u $domain/FUZZ -mc 200,201,202,203,303 -ignore-body -p 0.2 -of md -o $dir/exposedfiles/1-domain-exposed-files.txt >> /dev/null;
		cat $dir/exposedfiles/1-domain-exposed-files.txt | anew -q $dir/exposedfiles/mixed-exposedfiles.txt); done;

		echo -e "${GREEN}\n[$(date "+%H:%M:%S")]${ENDCOLOR} Saving results in clean format as ${GREEN}$dir/all-exposedfiles.txt${ENDCOLOR}"
		cat $dir/exposedfiles/mixed-exposedfiles.txt | grep -E "(http|https)://.*" | awk '{print $4}' | grep -E "^(http|https)://.*" | anew -q $dir/exposedfiles/all-exposedfiles.txt;
		rm $dir/exposedfiles/1-domain-exposed-files.txt $dir/exposedfiles/mixed-exposedfiles.txt;
		echo -e "${GREEN}\n[$(date "+%H:%M:%S")] 1-domain-exposed-files.txt${ENDCOLOR} & ${GREEN}mixed-exposedfiles.txt${ENDCOLOR} deleted"
		var=$(cat $dir/exposedfiles/all-exposedfiles.txt | wc -l)

		echo -e "${RED}[$(date "+%H:%M:%S")] $var exposed files/folders found & saved as > $target/exposedfiles/all-exposedfiles.txt${ENDCOLOR}"
		echo -e "${RED}[$(date "+%H:%M:%S")] $var exposed files/folders found & saved as > $target/exposedfiles/all-exposedfiles.txt${ENDCOLOR}"
		echo -e "${RED}[$(date "+%H:%M:%S")] $var exposed files/folders found & saved as > $target/exposedfiles/all-exposedfiles.txt${ENDCOLOR}"
		python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var exposed files/folders found\n\nFile saved as > $target/exposedfiles/all-exposedfiles.txt$")"
		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	else
		echo -e "${YELLOW}\n[$(date "+%H:%M:%S")] No discoverylist.txt found${ENDCOLOR} ";
		echo -e "${YELLOW}\n[$(date "+%H:%M:%S")] File/Folder bruteforce skipped!${ENDCOLOR} "
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}

# Jira vulnerabilities
function jiraya(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding JIRA vulnerabilities on $domain_count domains"
	python3 JIRAya.py -l $reconRanger/live-domains.txt | anew -q $output3/jiraya.txt;
	count=$(cat jiraya.txt | grep "The following vulnerabilities were found" | wc -l);

	# Found bug or not
	if [ $count -gt 0 ]; then
		echo -e "${RED}[$(date "+%H:%M:%S")] $count JIRA vulnerabilities found as saved as jiraya.txt${ENDCOLOR}"
	else
		echo -e "${RED}[$(date "+%H:%M:%S")]${ENDCOLOR} No JIRA vulnerabilities found"
		#rm $output3/jiraya.txt 2> /dev/null;
	fi
}

# Scanner | Completed
function xray(){
	cd xray/
	xin="../${reconRanger}"
	xout="../${output3}"

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Xray (Chinese tool)'s scan started";
	all_count=$(expr 60 \* $(expr $domain_count + $openport_count + $endpoint_count))
	if [ $all_count -ge 60 ]; then
	    hours=$(expr $all_count / 60)
	    minutes=$(expr $all_count % 60)
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Whole scan should take maximum ${GREEN}$hours hour(s) and $minutes minute(s)${ENDCOLOR}"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Whole scan should take maximum $all_count minute(s)"
	fi
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Enabled plugins: XSS, SQLi, CMDi, Path Traversal, Dirscan, Upload, Bruteforce, JSONp, Redirects, Struts, ThinkPHP, Shiro, FastJSON";
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] Configuration for SSRF, XXE and some other plugins left${ENDCOLOR}";

	# Live domains
	time1=$(expr $domain_count \* 60); time2=$(expr $domain_count \* 120); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing $domain_count live-domains (Approx $time1-$time2 minutes remaining)";
	for i in $(<$xin/live-domains.txt); do ./xray ws --basic-crawler $i --plugins xss,sqldet,cmd-injection,path-traversal,dirscan,upload,brute-force,jsonp,redirect,struts,thinkphp,shiro,fastjson >> $xout/xray.txt; done;
	check1=$(cat $xout/xray.txt | fgrep -o "[Vuln:" | wc -l);
	if [ $check1 -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] $check1 vulnerability found by Xray ${ENDCOLOR}"; fi;

	# Open ports
	time3=$(expr $openport_count \* 60); time4=$(expr $openport_count \* 120);	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing $openport_count Open Ports (Approx $time3-$time4 minutes remaining)";
	for i in $(<$xin/openports.txt); do ./xray ws --basic-crawler $i --plugins xss,sqldet,cmd-injection,path-traversal,dirscan,upload,brute-force,jsonp,redirect,struts,thinkphp,shiro,fastjson >> $xout/xray.txt ; done;
	check2=$(cat $xout/xray.txt | fgrep -o "[Vuln:" | wc -l);
	if [ "$check2" -gt "$check1" ]; then difference=$((check2 - check1)); echo -e "${RED}[$(date "+%H:%M:%S")] $difference new vulnerability found by Xray from open ports ${ENDCOLOR}"; fi;

	# Endpoints
	time5=$(expr $endpoint_count \* 60); time6=$(expr $endpoint_count \* 120); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing $endpoint_count endpoints (Approx $time5-$time6 minutes remaining)";
	for i in $(<$xin/endpoints.txt); do ./xray ws --basic-crawler $i --plugins xss,sqldet,cmd-injection,path-traversal,dirscan,upload,brute-force,jsonp,redirect,struts,thinkphp,shiro,fastjson >> $xout/xray.txt ; done;
	check3=$(cat $xout/xray.txt | fgrep -o "[Vuln:" | wc -l);
	if [ "$check3" -gt "$check2" ]; then difference2=$((check3 - check2)); echo -e "${RED}[$(date "+%H:%M:%S")] $difference2 new vulnerability found by Xray from endpoints ${ENDCOLOR}"; fi;

	# Files
	if [ -e $xout/xray.txt ]; then
		if [ $check3 -gt 0 ]; then
			echo -e "${RED}[$(date "+%H:%M:%S")] $check3 total vulnerability found by Xray > xray.txt${ENDCOLOR}";
			echo -e "${RED}[$(date "+%H:%M:%S")] Open file and find ${YELLOW}\"[Vuln:\"${ENDCOLOR}";
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No vulnerability found by Xray";
			rm $xout/xray.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Error: Unable to save Xray output${ENDCOLOR}";
		rm $xout/xray.txt;
	fi

	# Moved back to original directory
	cd - >> /dev/null

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: xray.txt
}

function find_backup_files(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding critical backup files by creating a dynamic wordlist based on the $domain_count domains";
	fuzzuli -f $reconRanger/live-domains.txt -mt all -es "tesla|twitter|google|bing|yahoo|facebook|instagram|yandex" >> $output3/fuzzuli.txt;

	# Check if anything found
	if [ -e $output3/fuzzuli.txt ]; then
		if [ -s $output3/fuzzuli.txt ]; then
			check=$(cat $output3/fuzzuli.txt | fgrep -o "[+]" | wc -l);
			echo -e "\n${RED}[$(date "+%H:%M:%S")] $check backup files found & saved as > 3-kc/fuzzuli.txt${ENDCOLOR}";
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No backup files found";
			rm $output3/fuzzuli.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error finding critical backup files for $target & Unable to create fuzzuli file";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: fuzzuli.txt
}

