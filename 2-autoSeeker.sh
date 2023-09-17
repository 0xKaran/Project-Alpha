#!/bin/bash

# Usage ./autoSeeker-2.sh 9ine
# Where 9ine is the folder name of target in /result

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

	# Creating 2autoSeeker folder
	if [ ! -d "$dir/2autoSeeker" ]; then
		mkdir -p $dir/2autoSeeker;
	fi

	# Variables
	reconRanger=$dir/1reconRanger;
	output2=$dir/2autoSeeker;
	folder_name=$target/2autoSeeker

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

function subdomain_takeover(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} CHECKING FOR ${GREEN}SUBDOMAIN TAKEOVER${ENDCOLOR} USING SUBZY"

	subzy run --targets $reconRanger/live-domains.txt --vuln --hide_fails | sed 1,7d | anew -q $output2/subdomain_takeover.txt;

	if [ -s "$output2/subdomain_takeover.txt" ]; then
	    var=$(cat $output2/subdomain_takeover.txt | wc -l);
	    echo -e "${RED}[$(date "+%H:%M:%S")] $var/$domain_count possible domains vulnerable to subdomain takeover";
	    echo -e "${RED}[$(date "+%H:%M:%S")] File saved as '$folder_name/subdomain_takeover.txt'";
	    #python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var possible domains vulnerable to subdomain takeover\n\nFile saved as > $target/subdomain_takeover.txt")"

	    #CNAME records checking to preciously extract potential domains for STO
	    function cname_checker(){
			if [ -s "$output2/subdomain_takeover.txt" ]; then
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} CHECKING ${GREEN}CNAME RECORDS${ENDCOLOR} TO EXTRACT POTENTIAL DOMAINS"	
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Making sure to pass only domains without protocol or special chars eg: 'sub.example.com'"
				grep -Eo '([a-zA-Z0-9.-]+)\.[a-zA-Z]{2,}' "$output2/subdomain_takeover.txt" | anew -q "$output2/check_cname.txt"

				# Function to check records
			    python3 ./cname_checker.py $output2/check_cname.txt | anew -q $output2/subdomain_takeover_cname.txt;

			    # Checking if anything found
				cname_file="$output2/subdomain_takeover_cname.txt"
				if [ -s "$cname_file" ]; then
				    all=$(wc -l < "$output2/subdomain_takeover.txt")
				    cname=$(grep -c "\[CNAME-DOMAIN\]" "$cname_file")

				    if (( cname >= 1 )); then
				        echo -e "${RED}[$(date "+%H:%M:%S")] $cname/$all have CNAME records${ENDCOLOR}"
				        echo -e "${RED}[$(date "+%H:%M:%S")] Verify error & CNAME point to get close to STO, saved as > $folder_name/subdomain_takeover_cname.txt${ENDCOLOR}"
				    	echo -e "${RED}[$(date "+%H:%M:%S")] For more info: https://github.com/EdOverflow/can-i-take-over-xyz";
				    else
				        echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CNAME records found for STO vulnerable domains, means they're false positive!"
				    	echo -e "${RED}[$(date "+%H:%M:%S")] For more info: https://github.com/EdOverflow/can-i-take-over-xyz";
				    fi
				fi
				rm -f $output2/check_cname.txt;
			fi
		}
		cname_checker

	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No vulnerable subdomain found"
	    rm $output2/subdomain_takeover.txt;
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
subdomain_takeover

function unauth_cache_purging(){
	# Domains
    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for ${GREEN}UnAuth-Cache-Purging${ENDCOLOR} vulnerability in $domain_count domains";
    for domain in $(<$reconRanger/live-domains.txt); do (curl -X PURGE -s $domain >> $output2/unAuthCachePurging.txt); done;

    # Endpoints
    if [ -e "$reconRanger/endpoints.txt" ]
	then
	  	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for UnAuth-Cache-Purging vulnerability in $endpoint_count endpoints";
    	for endpoint in $(<$reconRanger/endpoints.txt); do (curl -X PURGE -s $endpoint >> $output2/unAuthCachePurging.txt); done;
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'endpoints.txt' found ${ENDCOLOR} ";
	fi

	# Check if it found any vulnerable asset or not
	var=$(cat $output2/unAuthCachePurging.txt | grep '"status":' | wc -l);
	if [ "$var" -eq 0 ]; then
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No vulnerable asset found for UnAuth-Cache-Purging";
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} 'unAuthCachePurging.txt' deleted";
	    rm $output2/unAuthCachePurging.txt;
	else
	    echo -e "${RED}[$(date "+%H:%M:%S")] $var possible assets vulnerable to UnAuth-Cache-Purging vulnerability > $target/unAuthCachePurging.txt${ENDCOLOR}";
	    #python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var possible assets vulnerable to UnAuth-Cache-Purging vulnerability\n\nFile saved as > $target/unAuthCachePurging.txt")"
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
unauth_cache_purging

function config_file_finder(){

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for ${GREEN}config files${ENDCOLOR}"
	
	# Joomla----------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Joomla"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/book-a-demo") =~ '$dbtype' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] Joomla configuration file found @ $domain/configuration.php-dist${ENDCOLOR}"
		    echo "$domain/configuration.php-dist" | anew -q config_files.txt
		fi
		done	
	fi
	
	# Laravel----------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Laravel"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.env") =~ 'DB_DATABASE' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] Laravel configuration file found @ $domain/.env${ENDCOLOR}"
		    echo "$domain/.env" | anew -q config_files.txt
		fi
		done	
	fi

	# Laravel Log----------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Laravel Log"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/storage/logs/laravel.log" ) =~ 'laravel\framework' ]]; then
			echo -e "${RED}[$(date "+%H:%M:%S")] Laravel debug log file found @ $domain/storage/logs/laravel.log${ENDCOLOR}"
			echo "$domain/storage/logs/laravel.log" | anew -q $output2/config_files.txt
		fi
		done	
	fi
	
	# Zend----------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Zend"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/application/configs/application.ini") =~ 'resources.db.params.password' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] Zend configuration file found @ $domain/application/configs/application.ini${ENDCOLOR}"
		    echo "$domain/application/configs/application.ini" | anew -q $output2/config_files.txt
		fi
		done	
	fi

	# Wordpress Log----------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Wordpress"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/wp-content/debug.log" ) =~ 'PHP Notice: ' ]]; then
			echo -e "${RED}[$(date "+%H:%M:%S")] Wordpress debug log file found @ $domain/wp-content/debug.log${ENDCOLOR}"
			echo "$domain/wp-content/debug.log" | anew -q $output2/config_files.txt
		fi
		done	
	fi

	#----------------------------------------------------------------

	if [ -e "$output2/config_files.txt" ]
	then
	    var=$(cat $output2/config_files.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains exposing configuration files > $target/config_files.txt${ENDCOLOR}"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No configuration files found"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: config_files.txt
}
config_file_finder

function source_code_finder(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for ${GREEN}source code files${ENDCOLOR}"
	
	# .SVN----------------------------------------------------------------
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.svn/entries" ) =~ 'svn://' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .svn file found @ $domain/.svn/entries${ENDCOLOR}"
		    echo "$domain/.svn/entries" | anew -q source_code.txt
		fi
		done	
	fi

	# hgrc----------------------------------------------------------------
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.hg/hgrc" ) =~ '[paths]' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .hg/hgrc file found @ $domain/.hg/hgrc${ENDCOLOR}"
		    echo "$domain/.hg/hgrc" | anew -q source_code.txt
		fi
		done	
	fi

	# git----------------------------------------------------------------
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.git/HEAD" ) =~ 'ref: refs/heads/master' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .git/HEAD file found @ $domain/.git/HEAD${ENDCOLOR}"

		    echo "$domain/.git/HEAD" | anew -q source_code.txt
		fi
		done	
	fi

	# darcs----------------------------------------------------------------
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/_darcs/prefs/binaries" ) =~ 'Binary file regexps' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .git/HEAD file found @ $domain/_darcs/prefs/binaries${ENDCOLOR}"
		    echo -e "${RED}[$(date "+%H:%M:%S")] You can use 'https://github.com/arthaud/git-dumper'${ENDCOLOR}"
		    echo "$domain/_darcs/prefs/binaries" | anew -q source_code.txt
		fi
		done	
	fi

	# bazaar----------------------------------------------------------------
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.bzr/README" ) =~ 'This is a Bazaar control directory.' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .git/HEAD file found @ $domain/.bzr/README${ENDCOLOR}"
		    echo "$domain/.bzr/README" | anew -q source_code.txt
		fi
		done	
	fi

	#----------------------------------------------------------------

	if [ -e "$output2/source_code.txt" ]
	then
	    var=$(cat $output2/source_code.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains exposing source code files > $target/source_code.txt${ENDCOLOR}"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No source code files found"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	#Final: source_code.txt
}
source_code_finder

function dmarc(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking ${GREEN}DMARC vulnerability${ENDCOLOR}"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$reconRanger/live-domains.txt);
		do
			if [[ $(curl -ks -X GET "https://dmarcly.com/server/dmarc_check.php?domain=${SITE}") =~ 'success' ]]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $domain is vulnerable to DMARC${ENDCOLOR}"
				echo "$domain" | anew -q $output2/dmarc.txt
			fi
		done	
	fi

	#--------------------------------------------------------------
	if [ -e "$output2/dmarc.txt" ]
	then
	    var=$(cat $output2/dmarc.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains are vulnerable to DMARC > $target/dmarc.txt"
	    #python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var domains vulnerable to DMARC\n\nFile saved as > $target/dmarc.txt")"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No DMARC vulnerable domains found"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: dmarc.txt
}
dmarc

function spf(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking ${GREEN}missing SPF${ENDCOLOR} records"
	if [[ ! -f $reconRanger/live-domains.txt ]]; then
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
		for domain in $(<$reconRanger/live-domains.txt);
		do
		    domain=$(echo $domain | sed 's,http://,,; s,https://,,;') # remove protocol from domain name
		    if [[ $(curl -ks -d "serial=fred12&domain=$domain" -H "Content-Type: application/x-www-form-urlencoded" -X POST "https://www.kitterman.com/spf/getspf3.py") =~ 'No valid SPF record found' ]]; then
		        echo -e "${RED}[$(date "+%H:%M:%S")] Missing SPF record for : $domain${ENDCOLOR}"
		        echo "$domain" | anew -q $output2/spf.txt;
		    fi
		done
	fi

	#--------------------------------------------------------------
	if [ -e "$output2/spf.txt" ]
	then
	    var=$(cat $output2/spf.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains have missing SPF records > $target/spf.txt${ENDCOLOR}"
	    ##python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var domains have missing SPF records\n\nFile saved as > $target/spf.txt")"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} All domains are safe from email spoof attack"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: spf.txt
}
spf

function endpoints_downloader(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading endpoints locally to find harcoded stuffs"
	if [ -e "$reconRanger/endpoints.txt" ] && [ -s "$reconRanger/endpoints.txt" ] ; then
		
		var=$(cat $reconRanger/endpoints.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var URLs found in $target/endpoints.txt";
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloading in temp 'downloaded_endpoints' directory"
		time1=$(expr $var \* 4 \/ 60); time2=$(expr $var \* 5 \/ 60); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time1-$time2 minutes remaining";

		cat $reconRanger/endpoints.txt | concurl -c 5 -o $output2/downloaded_endpoints >> /dev/null;
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Downloaded files size: ${GREEN}$(du -m --max-depth=0 $output2/downloaded_endpoints/ | awk '{print $1}')M${ENDCOLOR}"
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Available  disk space: ${GREEN}$(df -h $0 | awk 'NR==2 {print $4}')${ENDCOLOR}"

		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Combining file contents as > $target/combined_endpoints_content_for_hardcoded_stuffs.txt"
		find $output2/downloaded_endpoints/ -type f -exec cat {} + > $output2/combined_endpoints_content_for_hardcoded_stuffs.txt;
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Done!";
		rm -r $output2/downloaded_endpoints/; echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} temp 'downloaded_endpoints' directory deleted";
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Either endpoints.txt is missing or the file is empty${ENDCOLOR}";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: combined_endpoints_content_for_hardcoded_stuffs.txt
}
endpoints_downloader

function hardcoded_stuffs_finder(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for ${GREEN}hardcoded stuffs${ENDCOLOR}"
	hardcoded_strings_file="./payloads/hardcoded_strings.txt"

	#----------------------------------------------------------------------------
	# All combined endpoints

	if [ -s "$hardcoded_strings_file" ]; then
		combined_endpoints_file="$output2/combined_endpoints_content_for_hardcoded_stuffs.txt"
		if [ -s "$combined_endpoints_file" ]; then
			fgrep -F -f "$hardcoded_strings_file" "$combined_endpoints_file" | anew -q "$output2/hardcoded_stuffs.txt";

			# Checking if anything found
			if [ -s "$output2/hardcoded_stuffs.txt" ]; then
				var=$(cat "$output2/hardcoded_stuffs.txt" | wc -l);
				echo -e "${RED}[$(date "+%H:%M:%S")] $var hardcoded strings found > $target/hardcoded_stuffs.txt ${ENDCOLOR}";
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var hardcoded strings found\n\nFile saved as > $target/hardcoded_stuffs.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No hardcoded stuff found!";
				rm $output2/hardcoded_stuffs.txt 2> /dev/null
			fi
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'combined_endpoints_content_for_hardcoded_stuffs.txt' file found in $target directory or the file is empty${ENDCOLOR}";
		fi
		
		#----------------------------------------------------------------------------
		# Checking in combined JS (1js.txt) as well

		combined_js_file="$reconRanger/1js.txt"
		if [ -s "$combined_js_file" ]; then
			fgrep -F -f "$hardcoded_strings_file" "$combined_js_file" | anew -q "$output2/hardcoded_stuffs.txt";

			# Checking if anything found
			if [ -s "$output2/hardcoded_stuffs.txt" ]; then
				var=$(cat "$output2/hardcoded_stuffs.txt" | wc -l);
				echo -e "${RED}[$(date "+%H:%M:%S")] $var hardcoded strings found > $target/hardcoded_stuffs.txt ${ENDCOLOR}";
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$var hardcoded strings found\n\nFile saved as > $target/hardcoded_stuffs.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No hardcoded stuff found in combined JS as well";
				rm $output2/hardcoded_stuffs.txt 2> /dev/null
			fi
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")] No '1js.txt' file found in $target directory or the file is empty ${ENDCOLOR}";
		fi

		#----------------------------------------------------------------------------

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'payloads/hardcoded_strings.txt' (matchers) file found${ENDCOLOR}";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: hardcoded_stuffs.txt
}
hardcoded_stuffs_finder

function domain_paths_concatenator(){

	if [ -f "$reconRanger/live-domains.txt" ] && [ -f "$reconRanger/expanded_paths.txt" ]; then
		# Read domain names from file
		domains=($(cat $reconRanger/live-domains.txt))

		# Read paths from file
		paths=($(cat $reconRanger/expanded_paths.txt))

		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Concatenating live-domains with expanded paths"
		# Loop through domains and paths to concatenate URLs
		for domain in "${domains[@]}"
		do
		    if [[ "$domain" == */ ]]; then
		        domain="${domain%/}"
		    fi

		    for path in "${paths[@]}"
		    do
		        if [[ "$path" != /* ]]; then
		            path="/$path"
		        fi

		        url="$domain$path"
		        echo "$url" | anew -q $reconRanger/expanded_paths_with_live-domains.txt;
		    done
		done

        # Checking file
        if [[ -s $reconRanger/expanded_paths_with_live-domains.txt ]]; then
		    var=$(cat $reconRanger/expanded_paths_with_live-domains.txt | wc -l);
		    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $var lines saved as > expanded_paths_with_live-domains.txt"	
		else
		    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Error concatenating domains/paths";
		    if [[ -e $reconRanger/expanded_paths_with_live-domains.txt ]]; then
		    	rm $reconRanger/expanded_paths_with_live-domains.txt;
		    	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Hence expanded_paths_with_live-domains.txt deleted"
		    fi
		fi

	else
	  echo -e "${YELLOW}[$(date "+%H:%M:%S")] Either live-domains.txt or paths.txt missing${ENDCOLOR}"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
domain_paths_concatenator

function put_method_finder(){

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}PUT method${ENDCOLOR} on $domain_count live-domains";
	if [ -e $reconRanger/live-domains.txt ]; then
		var3=$(cat $reconRanger/live-domains.txt | wc -l); time5=$(expr $var3 \* 1 \/ 60); time6=$(expr $var3 \* 2 \/ 60); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time5-$time6 minutes remaining";

		# Loop through the URLs in the file
		while read url; do
		    # Send a PUT request to the URL
		    response=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$url")
		    # Check if the response code is 200 OK
		    if [ "$response" == "200" ]; then
		    	((counter++))
		        echo $url | anew -q $output2/put_enabled_urls.txt;
		        echo -ne "$counter/$domain_count $(bc <<< "scale=0; $counter/$domain_count * 100")%\r" >&2
		    fi
		done < "$reconRanger/live-domains.txt"

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No live-domains.txt file found in $target";
	fi

	#------------------------------------------------------------------------------------------

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding PUT method on $endpoint_count endpoints";
	if [ -e $reconRanger/endpoints.txt ]; then
		var2=$(cat $reconRanger/endpoints.txt | wc -l); time3=$(expr $var2 \* 1 \/ 60); time4=$(expr $var2 \* 2 \/ 60); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time3-$time4 minutes remaining";

		# Loop through the URLs in the file
		while read url; do
		    # Send a PUT request to the URL
		    response=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$url")
		    # Check if the response code is 200 OK
		    if [ "$response" == "200" ]; then
		    	((counter++))
		        echo $url | anew -q $output2/put_enabled_urls.txt;
		        echo -ne "$counter/$endpoint_count $(bc <<< "scale=0; $counter/$endpoint_count * 100")%\r" >&2
		    fi
		done < "$reconRanger/endpoints.txt"

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No endpoints.txt file found in $target";
	fi

	#------------------------------------------------------------------------------------------

	exp_count=$(cat $reconRanger/expanded_paths_with_live-domains.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding PUT method on $exp_count expanded paths";
	if [ -s $reconRanger/expanded_paths_with_live-domains.txt ]; then
		var=$(cat $reconRanger/expanded_paths_with_live-domains.txt | wc -l); time1=$(expr $var \* 1 \/ 60); time2=$(expr $var \* 2 \/ 60); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time1-$time2 minutes remaining";

		# Loop through the URLs in the file
		while read url; do
		    # Send a PUT request to the URL
		    response=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$url")
		    # Check if the response code is 200 OK
		    if [ "$response" == "200" ]; then
		    	((counter++))
		        echo $url | anew -q $output2/put_enabled_urls.txt;
		        echo -ne "$counter/$exp_count $(bc <<< "scale=0; $counter/$exp_count * 100")%\r" >&2
		    fi
		done < "$reconRanger/expanded_paths_with_live-domains.txt"

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No expanded_paths_with_live-domains.txt file found in $target";
	fi

	#-------------------------------------------------------------------------------------------

	if [ -s $output2/put_enabled_urls.txt ]; then
		var4=$(cat $output2/put_enabled_urls.txt | wc -l);
		echo -e "${RED}[$(date "+%H:%M:%S")] $var4 locations have PUT method enabled${ENDCOLOR}";
		echo -e "${RED}[$(date "+%H:%M:%S")] File saved as $target/put_enabled_urls.txt${ENDCOLOR}";
		#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\nFound $var4 where HTTP PUT method is allowed\n\nFile saved as > $target/put_enabled_urls.txt")"
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No PUT enabled location found";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}
put_method_finder

function second_order_subdomain_takeover(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}second order subdomain takeover${ENDCOLOR}";

	# More/Associated domains
	if [ -s $reconRanger/more_domains.txt ]; then
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} more_domains.txt available${ENDCOLOR}";
		subzy run --targets $reconRanger/more_domains.txt --vuln --hide_fails | sed 1,7d | anew -q $output2/second_order_subdomain_takeover_vulnerable.txt;
	fi


	# From 3rd party domains in JS/HTML
	if [ -s $output2/combined_endpoints_content_for_hardcoded_stuffs.txt ]; then
		grep -Eo "(http[s]?|ftp|smtp):(//|\\/\\/)((localhost)|(127\.0\.0\.1)|(([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-\/]{2,}))[^\s\,\"]*" $output2/combined_endpoints_content_for_hardcoded_stuffs | sed -E 's/^[^:]+:\/\///' | sed 's/\/.*//' | sort -u > $output2/second_order_subdomain_takeover.txt;
		
		if [ -e $output2/second_order_subdomain_takeover.txt ]; then
			if [ -s $output2/second_order_subdomain_takeover.txt ]; then
				domain_count=$(cat $output2/second_order_subdomain_takeover.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking on $domain_count new third party domains";
				subzy run --targets $output2/second_order_subdomain_takeover.txt --vuln --hide_fails | sed 1,7d | anew -q $output2/second_order_subdomain_takeover_vulnerable.txt;
			else
				rm $output2/second_order_subdomain_takeover.txt
				echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No domain found from 'combined_endpoints_content_for_hardcoded_stuffs'";
			fi
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No domain found from 'combined_endpoints_content_for_hardcoded_stuffs'";
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No combined HTML & JS file as 'combined_endpoints_content_for_hardcoded_stuffs' found";
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Hence skipping";
	fi


	# Checking if found or not
	if [ -e $output2/second_order_subdomain_takeover_vulnerable.txt ]; then
		if [ -s $output2/second_order_subdomain_takeover_vulnerable.txt ]; then
			sost_count=$(cat $output2/second_order_subdomain_takeover_vulnerable.txt | grep VULNERABLE | wc -l);
			rm $output2/second_order_subdomain_takeover.txt
			echo -e "${RED}[$(date "+%H:%M:%S")] $sost_count domains possible for second order subdomain takeover${ENDCOLOR}";
			echo -e "${RED}[$(date "+%H:%M:%S")] Saved as > 2-aS/second_order_subdomain_takeover_vulnerable.txt${ENDCOLOR}";
			#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$sost_count domains possible for second order subdomain takeover\n\nFile saved as > $target/second_order_subdomain_takeover_vulnerable.txt")"
			echo -e "${RED}[$(date "+%H:%M:%S")] For more info: https://bit.ly/3LvjkDt${ENDCOLOR}";
		else
			rm $output2/second_order_subdomain_takeover.txt $output2/second_order_subdomain_takeover_vulnerable.txt;
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No domain vulnerable to second order subdomain takeover";
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No domain vulnerable to second order subdomain takeover";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: second_order_subdomain_takeover_vulnerable.txt
}
second_order_subdomain_takeover

function clickjacking(){
	#------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}Clickjacking${ENDCOLOR} on live-domains";
	total_live_domains=$(wc -l < $reconRanger/live-domains.txt)
	for domain in $(<$reconRanger/live-domains.txt); do
		if ! curl -s -I $domain | grep -q -i 'X-Frame-Options'; then
			echo $domain | anew -q $output2/clickjacking.txt; 
			
		    # Progress bar
			((counter++))
			echo -ne "${GREEN}[Progress]${ENDCOLOR} $counter/$total_live_domains $(bc <<< "scale=2; $counter/$total_live_domains * 100")%\r" >&2
		
		fi; done;

	#--------------------------------------------------------------

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding Clickjacking on endpoints";
	total_endpoints=$(wc -l < $reconRanger/endpoints.txt)
	for endpoint in $(<$reconRanger/endpoints.txt); do
		if ! curl -s -I $endpoint | grep -q -i 'X-Frame-Options'; then
			echo $endpoint | anew -q $output2/clickjacking.txt; 
			
		    # Progress bar
			((counter++))
			echo -ne "${GREEN}[Progress]${ENDCOLOR} $counter/$total_endpoints $(bc <<< "scale=2; $counter/$total_endpoints * 100")%\r" >&2
		
		fi; done;

	#Checking --------------------------------------------------------------

	if [ -e $output2/clickjacking.txt ]; then
		if [ -s $output2/clickjacking.txt ]; then
			cljk_count=$(cat $output2/clickjacking.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $cljk_count urls/domains have Clickjacking vulnerability${ENDCOLOR}";
			echo -e "${RED}[$(date "+%H:%M:%S")] Saved as > clickjacking.txt ${ENDCOLOR}";
			#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$cljk_count urls/domains have Clickjacking vulnerability\n\nFile saved as > $target/clickjacking.txt")"
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} clickjacking.txt is empty";
			rm $output2/clickjacking.txt;
		fi

	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No clickjacking found";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: clickjacking.txt
}
clickjacking

function cors(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}Cross Origin Resource Sharing (CORS)${ENDCOLOR} misconfig in live-domains"
	total_live_domains=$(wc -l < $reconRanger/live-domains.txt)
	time_min=$(expr $total_live_domains \* 25 / 60)
	time_max=$(expr $total_live_domains \* 35 / 60)
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time_min-$time_max minutes remaining"
	
	for domain in $(<$reconRanger/live-domains.txt); do
		python3 corsy/corsy.py -u $domain -t 20 >> $output2/cors.txt

		# Progress bar
		((counter++))
		echo -ne "${GREEN}[Progress]${ENDCOLOR} $counter/$total_live_domains $(bc <<< "scale=2; $counter/$total_live_domains * 100")%\r" >&2
	done

	#Check --------------------------------------------------------------

	if [ -e $output2/cors.txt ]; then
		if [ -s $output2/cors.txt ]; then
			cors_count=$(grep -E "(http[s]?:)" $output2/cors.txt | grep -v "ACAO" | sort -u | wc -l)
			if [ $cors_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $cors_count CORS misconfig found > $target/cors.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$cors_count CORS misconfig found\n\nFile saved as > $target/cors.txt")"

				# Severity Count
				high=$(grep -c "Severity: high" $output2/cors.txt)
				medium=$(grep -c "Severity: medium" $output2/cors.txt)
				low=$(grep -c "Severity: low" $output2/cors.txt)

				if [ $high -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] High Severity: $high${ENDCOLOR}"; fi
				if [ $medium -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] Medium Severity: $medium${ENDCOLOR}"; fi
				if [ $low -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] Low Severity: $low${ENDCOLOR}"; fi
				echo -e "${RED}[$(date "+%H:%M:%S")] Read ./scripts/corsy/db/details.json for exploitation${ENDCOLOR}"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CORS misconfigs found"
			fi
		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error performing CORS check"
		fi
	else
		rm $output2/cors.txt
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error performing CORS check"
	fi

	# --------------------------------------------------------------

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding CORS misconfig in endpoints"
	time_min2=$(expr $total_live_domains \* 25 / 60)
	time_max2=$(expr $total_live_domains \* 35 / 60)
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time_min2-$time_max2 minutes remaining"
	total_endpoints=$(wc -l < $reconRanger/endpoints.txt)
	for endpoint in $(<$reconRanger/endpoints.txt); do
		
		python3 corsy/corsy.py -u $endpoint -t 20 >> $output2/cors.txt

	    # Progress bar
		((counter++))
		echo -ne "${GREEN}[Progress]${ENDCOLOR} $counter/$total_endpoints $(bc <<< "scale=2; $counter/$total_endpoints * 100")%\r" >&2
		
		done;

	#--------------------------------------------------------------

	if [ -e $output2/cors.txt ]; then
		if [ -s $output2/cors.txt ]; then
			cors_count2=$(cat $output2/cors.txt | grep -E "(http[s]?:)" | grep -v "ACAO" | sort -u | wc -l);
			diff=$((cors_count2 - cors_count))

			# Check if the difference is greater than zero
			if ((diff > 0)); then
				# Severity Count
				high2=$(grep -c "Severity: high" $output2/cors.txt); hi_diff=$((high2 - high));
				medium2=$(grep -c "Severity: medium" $output2/cors.txt); med_diff=$((medium2 - medium));
				low2=$(grep -c "Severity: low" $output2/cors.txt); low_diff=$((low2 - low));

				if [ $hi_diff -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] $hi_diff new high severity CORS misconfig found${ENDCOLOR}"; fi
				if [ $med_diff -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] $med_diff new medium severity CORS misconfig found${ENDCOLOR}"; fi
				if [ $low_diff -gt 0 ]; then echo -e "${RED}[$(date "+%H:%M:%S")] $low_diff new low severity CORS misconfig found${ENDCOLOR}"; fi
				echo -e "${RED}[$(date "+%H:%M:%S")] All saved as > $target/cors.txt${ENDCOLOR}";
				echo -e "${RED}[$(date "+%H:%M:%S")] Read ./scripts/corsy/db/details.json for exploitation${ENDCOLOR}";

			else
			    echo -e "${GREEN}[$(date "+%H:%M:%S")] No CORS misconfig found in endpoints${ENDCOLOR}";
			fi

		else
			echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error performing CORS check";
		fi
	else
		rm $output2/cors.txt;
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error performing CORS check";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: cors.txt
}
cors

function wordpress_scan(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}WordPress vulnerabilities${ENDCOLOR}"

	# Scan---------------------------------------------------------------
	
	for domain in $(<$reconRanger/live-domains.txt); do 
	  domain_no_proto=$(echo $domain | sed 's/^https\?:\/\///')
	  scan_output=$(wpscan --url $domain_no_proto --enumerate u --api-token geayt3Ao5ySk3ONle2XmJfHu6tjmtW0wdsPYsHayuqg >> $output2/wpscan.txt);
	  ((counter++))
	  echo -ne "\r${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Scanning $counter/$domain_count ($(bc <<< "scale=2; $counter/$domain_count * 100")%): $domain_no_proto";
	done
	echo -ne "\r";

	findings=$(cat $output2/wpscan.txt | grep -o "Interesting Finding" | wc -l);
	userfindings=$(cat $output2/wpscan.txt | grep -o "User(s) Identified" | wc -l);

	# Checking issue---------------------------------------------------------------

	if [ $findings -gt 0 ]; then
		echo -e "${RED}[$(date "+%H:%M:%S")] $findings interesting things found during wordpress scan > $target/wpscan.txt${ENDCOLOR}";
		#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$findings interesting things found during wordpress scan\n\nFile saved as > $target/wpscan.txt")"
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No WordPress issue was found, or WordPress may not be running";
	fi

	# Checking users---------------------------------------------------------------
	
	if [ $userfindings -gt 0 ]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] Few users also found${ENDCOLOR}";
	fi

	# Deleting file---------------------------------------------------------------
	
	if [ $findings -eq 0 ] && [ $userfindings -eq 0 ]; then
	  rm $output2/wpscan.txt
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: wpscan.txt
}
wordpress_scan

function crlf(){
	# domain GET---------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}CRLF${ENDCOLOR} vulnerability in $domain_count live-domains - [${GREEN}GET${ENDCOLOR}]"
	var1=$(cat $reconRanger/live-domains.txt | wc -l); time1=$(expr $var1 \* 3 \/ 60); time2=$(expr $var1 \* 5 \/ 60); if (( $(echo "$time2 - $time1 < 1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} less than 1 min remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time1-$time2 minutes remaining"; fi
	crlfuzz -l $reconRanger/live-domains.txt -silent -o $output2/crlf-domain-GET.txt;

		# File check
		if [[ -e $output2/crlf-domain-GET.txt && -s $output2/crlf-domain-GET.txt ]]; then
			dom_get_count=$(cat $output2/crlf-domain-GET.txt | wc -l);
			if [ $dom_get_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $dom_get_count domains vulnerable to CRLF attack & saved as > $target/crlf-domain-GET.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$dom_get_count domains vulnerable to CRLF attack\n\nFile saved as > $target/crlf-domain-GET.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in live-domains via GET method"
				rm -f $output2/crlf-domain-GET.txt
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in live-domains via GET method"
			rm -f $output2/crlf-domain-GET.txt
		fi

	# domain POST---------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding CRLF vulnerability in $domain_count live-domains - [${GREEN}POST${ENDCOLOR}]"
	if (( $(echo "$time2 - $time1 < 1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} less than 1 min remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time1-$time2 minutes remaining"; fi
	crlfuzz -l $reconRanger/live-domains.txt -X POST -silent -o $output2/crlf-domain-POST.txt;

		# File check
		if [[ -e $output2/crlf-domain-POST.txt && -s $output2/crlf-domain-POST.txt ]]; then
			dom_post_count=$(cat $output2/crlf-domain-POST.txt | wc -l);
			if [ $dom_post_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $dom_post_count domains vulnerable to CRLF attack & saved as > $target/crlf-domain-POST.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$dom_post_count domains vulnerable to CRLF attack\n\nFile saved as > $target/crlf-domain-POST.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in live-domains via POST method"
				rm -f $output2/crlf-domain-POST.txt
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in live-domains via POST method"
			rm -f $output2/crlf-domain-POST.txt
		fi

	# openports GET---------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}CRLF${ENDCOLOR} vulnerability in $openport_count openports - [${GREEN}GET${ENDCOLOR}]"
	crlfuzz -l $reconRanger/openports.txt -silent -o $output2/crlf-openports-GET.txt;

		# File check
		if [[ -e $output2/crlf-openports-GET.txt && -s $output2/crlf-openports-GET.txt ]]; then
			opp_get_count=$(cat $output2/crlf-openports-GET.txt | wc -l);
			if [ $opp_get_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $opp_get_count openports domains vulnerable to CRLF attack & saved as > $target/crlf-openports-GET.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$dom_get_count domains vulnerable to CRLF attack\n\nFile saved as > $target/crlf-domain-GET.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in openports via GET method"
				rm -f $output2/crlf-openports-GET.txt
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in openports via GET method"
			rm -f $output2/crlf-openports-GET.txt
		fi

	# openports POST---------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}CRLF${ENDCOLOR} vulnerability in $openport_count openports - [${GREEN}POST${ENDCOLOR}]"
	crlfuzz -l $reconRanger/openports.txt -X POST -silent -o $output2/crlf-openports-POST.txt;

		# File check
		if [[ -e $output2/crlf-openports-POST.txt && -s $output2/crlf-openports-POST.txt ]]; then
			opp_post_count=$(cat $output2/crlf-openports-POST.txt | wc -l);
			if [ $opp_post_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $opp_post_count openports domains vulnerable to CRLF attack & saved as > $target/crlf-openports-POST.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$dom_get_count domains vulnerable to CRLF attack\n\nFile saved as > $target/crlf-domain-GET.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in openports via GET method"
				rm -f $output2/crlf-openports-POST.txt
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in openports via GET method"
			rm -f $output2/crlf-openports-POST.txt
		fi

	# more_domains GET---------------------------------------------------------------------
	if [ -s $reconRanger/more_domains.txt ]; then
		more_domain_count=$(cat $reconRanger/more_domains.txt | wc -l)
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}CRLF${ENDCOLOR} vulnerability in $more_domain_count more_domains - [${GREEN}GET${ENDCOLOR}]"
		crlfuzz -l $reconRanger/more_domains.txt -silent -o $output2/crlf-more_domains-GET.txt;

			# File check
			if [[ -e $output2/crlf-more_domains-GET.txt && -s $output2/crlf-more_domains-GET.txt ]]; then
				md_get_count=$(cat $output2/crlf-more_domains-GET.txt | wc -l);
				if [ $md_get_count -gt 0 ]; then
					echo -e "${RED}[$(date "+%H:%M:%S")] $md_get_count more_domains domains vulnerable to CRLF attack & saved as > $target/crlf-more_domains-GET.txt${ENDCOLOR}"
					#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$dom_get_count domains vulnerable to CRLF attack\n\nFile saved as > $target/crlf-domain-GET.txt")"
				else
					echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in more_domains via GET method"
					rm -f $output2/crlf-more_domains-GET.txt
				fi
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in more_domains via GET method"
				rm -f $output2/crlf-more_domains-GET.txt
			fi
	fi

	# more_domains POST---------------------------------------------------------------------
	if [ -s $reconRanger/more_domains.txt ]; then
		more_domain_count=$(cat $reconRanger/more_domains.txt | wc -l)
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}CRLF${ENDCOLOR} vulnerability in $more_domain_count more_domains - [${GREEN}POST${ENDCOLOR}]"
		crlfuzz -l $reconRanger/more_domains.txt -X POST -silent -o $output2/crlf-more_domains-POST.txt;

			# File check
			if [[ -e $output2/crlf-more_domains-POST.txt && -s $output2/crlf-more_domains-POST.txt ]]; then
				md_post_count=$(cat $output2/crlf-more_domains-POST.txt | wc -l);
				if [ $md_post_count -gt 0 ]; then
					echo -e "${RED}[$(date "+%H:%M:%S")] $md_post_count more_domains domains vulnerable to CRLF attack & saved as > $target/crlf-more_domains-POST.txt${ENDCOLOR}"
					#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$dom_get_count domains vulnerable to CRLF attack\n\nFile saved as > $target/crlf-domain-POST.txt")"
				else
					echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in more_domains via POST method"
					rm -f $output2/crlf-more_domains-POST.txt
				fi
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in more_domains via POST method"
				rm -f $output2/crlf-more_domains-POST.txt
			fi
	fi

	# endpoints GET---------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding CRLF vulnerability in $endpoint_count endpoints - [${GREEN}GET${ENDCOLOR}]"
	var2=$(cat $reconRanger/live-domains.txt | wc -l); time3=$(expr $var2 \* 3 \/ 60); time4=$(expr $var2 \* 5 \/ 60); if (( $(echo "$time4 - $time3 < 1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} less than 1 min remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time3-$time4 minutes remaining"; fi
	crlfuzz -l $reconRanger/endpoints.txt -silent -o $output2/crlf-endpoints-GET.txt;

		# File check
		if [[ -e $output2/crlf-endpoints-GET.txt && -s $output2/crlf-endpoints-GET.txt ]]; then
			endpoint_get_count=$(cat $output2/crlf-endpoints-GET.txt | wc -l);
			if [ $endpoint_get_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $endpoint_get_count endpoints vulnerable to CRLF attack & saved as > $target/crlf-endpoints-GET.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$endpoint_get_count endpoints vulnerable to CRLF attack\n\nFile saved as > $target/crlf-endpoints-GET.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in endpoints via GET method"
				rm -f $output2/crlf-endpoints-GET.txt
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in endpoints via GET method"
			rm -f $output2/crlf-endpoints-GET.txt
		fi

	# endpoints POST---------------------------------------------------------------------
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding CRLF vulnerability in $endpoint_count endpoints - [${GREEN}POST${ENDCOLOR}]"
	if (( $(echo "$time4 - $time3 < 1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} less than 1 min remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $time3-$time4 minutes remaining"; fi
	crlfuzz -l $reconRanger/endpoints.txt -X POST -silent -o $output2/crlf-endpoints-POST.txt;

		# File check
		if [[ -e $output2/crlf-endpoints-POST.txt && -s $output2/crlf-endpoints-POST.txt ]]; then
			endpoint_post_count=$(cat $output2/crlf-endpoints-POST.txt | wc -l);
			if [ $endpoint_post_count -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $endpoint_post_count endpoints vulnerable to CRLF attack & saved as > $target/crlf-endpoints-POST.txt${ENDCOLOR}"
				#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$endpoint_post_count endpoints vulnerable to CRLF attack\n\nFile saved as > $target/crlf-endpoints-POST.txt")"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in endpoints via POST method"
				rm -f $output2/crlf-endpoints-POST.txt
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No CRLF found in endpoints via POST method"
			rm -f $output2/crlf-endpoints-POST.txt
		fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: crlf-domain-GET.txt, crlf-domain-POST.txt, crlf-endpoints-GET.txt, crlf-endpoints-POST.txt
}
crlf

function host_header_injection_hinject(){
	
	# Test on endpoints
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding ${GREEN}host header injection${ENDCOLOR} on endpoints with hinject"
	if (( $(echo "($endpoint_count*5/60)-($endpoint_count*7/60)<1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Less than 3 mins remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $(expr $endpoint_count \* 5 / 60)-$(expr $endpoint_count \* 7 / 60) minutes remaining"; fi
	for url in $(<$reconRanger/endpoints.txt);
	do echo $url | hinject -v | anew -q $output2/host_header_injection_hinject_unfiltered.txt;
	done;



	# Test on live-domains
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding host header injection on live-domains with hinject"
	if (( $(echo "($domain_count*5/60)-($domain_count*7/60)<1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Less than 3 mins remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $(expr $domain_count \* 5 / 60)-$(expr $domain_count \* 7 / 60) minutes remaining"; fi
	for domain in $(<$reconRanger/live-domains.txt);
	do echo $domain | hinject -v | anew -q $output2/host_header_injection_hinject_unfiltered.txt;
	done;



	# Test on open ports
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Finding host header injection on open ports with hinject"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} First checking accessible port with httpx"
	if [ -e $reconRanger/openports.txt ] && [ -s $reconRanger/openports.txt ]; then
		openports_count=$(cat $reconRanger/openports.txt | wc -l);
		if (( $(echo "($openports_count*5/60)-($openports_count*7/60)<1" | bc -l) )); then echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Less than 3 mins remaining"; else echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Approx $(expr $openports_count \* 5 / 60)-$(expr $openports_count \* 7 / 60) minutes remaining"; fi
		
		for asset in $(<$reconRanger/openports.txt);
		do
			((counter++))
			accessible=$(echo $asset | httpx -silent); echo $accessible | hinject -v | anew -q $output2/host_header_injection_hinject_unfiltered.txt;
			echo -ne "${GREEN}[Progress]${ENDCOLOR} $counter/$openports_count $(bc <<< "scale=2; $counter/$openports_count * 100")%\r" >&2
		done;
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No openports.txt file found or file is empty for $target"
	fi



	# Extraction of possible vulnerable urls
	cat $output2/host_header_injection_hinject_unfiltered.txt | grep "VULNERABLE" | anew -q $output2/host_header_injection_hinject.txt;
	rm $output2/host_header_injection_hinject_unfiltered.txt


	# Counting how many found
	if [ -e $output2/host_header_injection_hinject.txt ]; then
		if [ -s $output2/host_header_injection_hinject.txt ]; then
			count=$(cat $output2/host_header_injection_hinject.txt | wc -l);
			echo -e "${RED}[$(date "+%H:%M:%S")] $count endpoints seem to be host header injection vulnerable ${ENDCOLOR}"
			echo -e "${RED}[$(date "+%H:%M:%S")] Manual check needed > $target/host_header_injection_hinject.txt ${ENDCOLOR}"
			#python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\n$count endpoints seem to be host header injection vulnerable\n\nManual check needed\n\nFile saved as > $target/host_header_injection_hinject.txt")"
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No host header injection vulnerability found in live domains, endpoints & open ports"
			rm $output2/host_header_injection_hinject.txt
		fi
	else
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No host header injection vulnerability found in live domains, endpoints & open ports"
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: host_header_injection_hinject.txt
}
host_header_injection_hinject

function social_media_takeover(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for ${GREEN}social media takeover${ENDCOLOR} on $domain_count live-domains"
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Socialhunter will crawl & look for social media links"

	# Live domains
	socialhunter -f $reconRanger/live-domains.txt >> $output2/socialhunter.txt;

	# open ports
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for social media takeover on $openport_count openports"
	cat $reconRanger/openports.txt | httpx -silent -no-color | anew -q $reconRanger/temp_port_domains_with_protocol.txt;
	socialhunter -f $reconRanger/temp_port_domains_with_protocol.txt >> $output2/socialhunter.txt;
	rm $reconRanger/temp_port_domains_with_protocol.txt;

	# Endpoints
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for social media takeover on $endpoint_count endpoints"
	socialhunter -f $reconRanger/endpoints.txt >> $output2/socialhunter.txt;

	# Expanded paths
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for social media takeover on expanded_paths"
	socialhunter -f $reconRanger/expanded_paths_with_live-domains.txt >> $output2/socialhunter.txt;

	# Check if anything found
	if [ -e $output2/socialhunter.txt ]; then
		if [ -s $output2/socialhunter.txt ]; then
			check=$(cat $output2/socialhunter.txt | fgrep -o "Possible Takeover" | wc -l);

			if [ $check -gt 0 ]; then	
				echo -e "\n${RED}[$(date "+%H:%M:%S")] $check social media accounts possible to takeover & saved as > 2-as/socialhunter.txt${ENDCOLOR}";
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No possible takeover found";
				rm $output2/socialhunter.txt;
			fi

		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No possible takeover found";
			rm $output2/socialhunter.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Something went wrong, unable to check social media takeover";
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: socialhunter.txt
}
social_media_takeover

function chopchop(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Quickly finding ${GREEN}exposed critical endpoints${ENDCOLOR} on $domain_count live-domains using ChopChop"
	cd ChopChop
	xin="../${reconRanger}"
	xout="../${output2}"


	# Live domains
	for domain in $(<$xin/live-domains.txt); do ./gochopchop scan $domain >> $xout/chopchop.txt; done;
	
	# Checking
	if [ -e $xout/chopchop.txt ]; then
		if [ -s $xout/chopchop.txt ]; then
			domcount=$(tail -n +3 $xout/chopchop.txt | grep -c "^|";);
			if [ $domcount -gt 0 ]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $domcount endpoints found${ENDCOLOR}"
			else
				echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Nothing found"
				rm $xout/chopchop.txt;
			fi
		else
			echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Nothing found";
			rm $xout/chopchop.txt;
		fi
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Error running ChopChop, no file was created!"
	fi

	cd - >> /dev/null

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: chopchop.txt
}
chopchop

function testssl(){
	# Check on live-domains
	domain_count=$(cat $reconRanger/live-domains.txt | wc -l); time1=$(expr $domain_count \* 3); time2=$(expr $domain_count \* 4);
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing ${GREEN}TLS/SSL encryption${ENDCOLOR} on $domain_count live-domains";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take time | approx $time1-$time2 minutes remaining";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} It can't be stopped so ${YELLOW}avoid pressing 'ctrl+c'${ENDCOLOR}";
	for domain in $(<$reconRanger/live-domains.txt); do (./testssl/testssl.sh $domain >> $output2/testssl.txt); done;

	# Check on open ports domain
    if [ -e "$reconRanger/openports.txt" ]
	then
		var=$(<$reconRanger/openports.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing TLS/SSL encryption on open ports for $var domains";
		openports_domain_count=$(cat $reconRanger/openports.txt | wc -l); time3=$(expr $openports_domain_count \* 3); time4=$(expr $openports_domain_count \* 4);
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take time | approx $time3-$time4 minutes remaining";
		for domain in $(<$reconRanger/openports.txt); do (./testssl/testssl.sh $domain >> $output2/testssl.txt); done;
	else
		echo -e "\n\n\n${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No \"openports.txt\" found";
	fi

	# Saved output
	if [ -s "$reconRanger/openports.txt" ]; then
	  echo -e "${YELLOW}[$(date "+%H:%M:%S")] TLS/SSL encryption result saved as > $target/testssl.txt${ENDCOLOR}";
	  echo -e "${RED}[$(date "+%H:%M:%S")] Need to be checked manually${ENDCOLOR}";
	  echo -e "${RED}[$(date "+%H:%M:%S")] Need to be checked manually${ENDCOLOR}";
	  #python3 notification.py "$(echo -e "[ $(date "+%H:%M:%S") ] [ *$target* ] [ 2-autoSeeker ]\n\nTestSSL result saved as $target/testssl.txt\n\nManual check still needed!")"
	else
	  echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Something went wrong! No result found for TLS/SSL encryption";
	  rm $output2/testssl.txt;
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: $output2/testssl.txt
}
testssl
