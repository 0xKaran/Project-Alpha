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

	domain_count=$(cat $dir/live-domains.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Performing automated testing on ${GREEN}$domain_count live domains${ENDCOLOR}"

function subdomain_takeover(){
	echo -e "\n${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking for subdomain takeover using Subzy"

	subzy run --targets $dir/live-domains.txt --vuln --hide_fails | sed 1,7d | anew -q $dir/subdomain_takeover.txt;

	if [ -s "$dir/subdomain_takeover.txt" ]; then
	    var=$(cat $dir/subdomain_takeover.txt | wc -l);
	    echo -e "${RED}[$(date "+%H:%M:%S")] $var possible domains vulnerable to subdomain takeover";
	    echo -e "${RED}[$(date "+%H:%M:%S")] File saved as '$(pwd)/subdomain_takeover.txt'";
	    echo -e "${red}-------------------------------------------------";
	    echo -e "${red}-------------------------------------------------";
	    cat $dir/subdomain_takeover.txt | grep -oP '(?<=\/\/)[^\/]+'
	    echo -e "${red}-------------------------------------------------";
	    echo -e "${red}-------------------------------------------------${ENDCOLOR}";
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No vulnerable subdomain found for takeover hence ${GREEN}subdomain_takeover.txt${ENDCOLOR} deleted"
	    rm $dir/subdomain_takeover.txt;
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}

function exposedfiles(){
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

		echo -e "${RED}[$(date "+%H:%M:%S")] $var exposed files/folders found & saved as \"$dir/exposedfiles/all-exposedfiles.txt\"${ENDCOLOR}"
		echo -e "${RED}[$(date "+%H:%M:%S")] $var exposed files/folders found & saved as \"$dir/exposedfiles/all-exposedfiles.txt\"${ENDCOLOR}"
		echo -e "${RED}[$(date "+%H:%M:%S")] $var exposed files/folders found & saved as \"$dir/exposedfiles/all-exposedfiles.txt\"${ENDCOLOR}"
		echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	else
		echo -e "${YELLOW}\n[$(date "+%H:%M:%S")] No discoverylist.txt found${ENDCOLOR} ";
		echo -e "${YELLOW}\n[$(date "+%H:%M:%S")] File/Folder bruteforce skipped!${ENDCOLOR} "
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}

function unauth_cache_purging(){
	# Domains
    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for UnAuth-Cache-Purging vulnerability in domains";
    for domain in $(<$dir/live-domains.txt); do (curl -X PURGE -s $domain >> $dir/unAuthCachePurging.txt); done;

    # Endpoints
    if [ -e "$dir/endpoints.txt" ]
	then
	  	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for UnAuth-Cache-Purging vulnerability in endpoints";
    	for endpoint in $(<$dir/endpoints.txt); do (curl -X PURGE -s $endpoint >> $dir/unAuthCachePurging.txt); done;
	else
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'endpoints.txt' found ${ENDCOLOR} ";
	fi

	# Check if it found any vulnerable asset or not
	var=$(cat $dir/unAuthCachePurging.txt | grep '"status":' | wc -l);
	if [ "$var" -eq 0 ]; then
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No vulnerable asset found for UnAuth-Cache-Purging";
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} 'unAuthCachePurging.txt' deleted";
	    rm $dir/unAuthCachePurging.txt;
	else
	    echo -e "${RED}[$(date "+%H:%M:%S")] $var possible assets vulnerable to UnAuth-Cache-Purging vulnerability >> $dir/unAuthCachePurging.txt${ENDCOLOR}";
	fi
	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
}

function testssl(){
	# Check on live-domains
	domain_count=$(cat $dir/live-domains.txt | wc -l); time1=$(expr $domain_count \* 3); time2=$(expr $domain_count \* 4);
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing TLS/SSL encryption on $domain_count live-domains";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take time | approx $time1-$time2 minutes remaining";
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} It can't be stopped so ${YELLOW}avoid pressing 'ctrl+c'${ENDCOLOR}";
	for domain in $(<$dir/live-domains.txt); do (./testssl/testssl.sh $domain >> $dir/testssl.txt); done;

	# Check on open ports domain
    if [ -e "$dir/openports.txt" ]
	then
		var=$(<$dir/openports.txt | wc -l); echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Testing TLS/SSL encryption on open ports for $var domains";
		openports_domain_count=$(cat $dir/openports.txt | wc -l); time3=$(expr $openports_domain_count \* 3); time4=$(expr $openports_domain_count \* 4);
		echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} This may take time | approx $time3-$time4 minutes remaining";
		for domain in $(<$dir/openports.txt); do (./testssl/testssl.sh $domain >> $dir/testssl.txt); done;
	else
		echo -e "\n\n\n${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} No \"openports.txt\" found";
	fi

	# Saved output
	if [ -s "$dir/openports.txt" ]; then
	  echo -e "${YELLOW}[$(date "+%H:%M:%S")] TLS/SSL encryption result saved as '$2/testssl.txt'${ENDCOLOR}";
	  echo -e "${RED}[$(date "+%H:%M:%S")] Need to be checked manually${ENDCOLOR}";
	  echo -e "${RED}[$(date "+%H:%M:%S")] Need to be checked manually${ENDCOLOR}";
	else
	  echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} Something went wrong! No result found for TLS/SSL encryption";
	  rm $dir/testssl.txt;
	fi

	echo -e "${GREEN}-------------------------------------------------${ENDCOLOR}";
	# Final: $dir/testssl.txt
}

function config_file_finder(){

	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for config files"
	
	# Joomla----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/book-a-demo") =~ '$dbtype' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] Joomla configuration file found @ $domain/configuration.php-dist${ENDCOLOR}"
		    echo "$domain/configuration.php-dist" | anew -q config_files.txt
		fi
		done	
	fi
	
	# Laravel----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.env") =~ 'DB_DATABASE' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] Laravel configuration file found @ $domain/.env${ENDCOLOR}"
		    echo "$domain/.env" | anew -q config_files.txt
		fi
		done	
	fi
	
	# Zend----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/application/configs/application.ini") =~ 'resources.db.params.password' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] Zend configuration file found @ $domain/application/configs/application.ini${ENDCOLOR}"
		    echo "$domain/application/configs/application.ini" | anew -q $dir/config_files.txt
		fi
		done	
	fi

	# Wordpress Log----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/wp-content/debug.log" ) =~ 'PHP Notice: ' ]]; then
			echo -e "${RED}[$(date "+%H:%M:%S")] Wordpress debug log file found @ $domain/wp-content/debug.log${ENDCOLOR}"
			echo "$domain/wp-content/debug.log" | anew -q $dir/config_files.txt
		fi
		done	
	fi

	# Laravel Log----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
		echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/storage/logs/laravel.log" ) =~ 'laravel\framework' ]]; then
			echo -e "${RED}[$(date "+%H:%M:%S")] Laravel debug log file found @ $domain/storage/logs/laravel.log${ENDCOLOR}"
			echo "$domain/storage/logs/laravel.log" | anew -q $dir/config_files.txt
		fi
		done	
	fi
	#----------------------------------------------------------------

	if [ -e "$dir/config_files.txt" ]
	then
	    var=$(cat $dir/config_files.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains exposing configuration files > $target/config_files.txt${ENDCOLOR}"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No configuration files found"
	fi
}

function source_code_finder(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Looking for source code files"
	
	# .SVN----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.svn/entries" ) =~ 'svn://' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .svn file found @ $domain/.svn/entries${ENDCOLOR}"
		    echo "$domain/.svn/entries" | anew -q source_code.txt
		fi
		done	
	fi

	# hgrc----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.hg/hgrc" ) =~ '[paths]' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .hg/hgrc file found @ $domain/.hg/hgrc${ENDCOLOR}"
		    echo "$domain/.hg/hgrc" | anew -q source_code.txt
		fi
		done	
	fi

	# git----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.git/HEAD" ) =~ 'ref: refs/heads/master' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .git/HEAD file found @ $domain/.git/HEAD${ENDCOLOR}"

		    echo "$domain/.git/HEAD" | anew -q source_code.txt
		fi
		done	
	fi

	# darcs----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/_darcs/prefs/binaries" ) =~ 'Binary file regexps' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .git/HEAD file found @ $domain/_darcs/prefs/binaries${ENDCOLOR}"
		    echo -e "${RED}[$(date "+%H:%M:%S")] You can use 'https://github.com/arthaud/git-dumper'${ENDCOLOR}"
		    echo "$domain/_darcs/prefs/binaries" | anew -q source_code.txt
		fi
		done	
	fi

	# bazaar----------------------------------------------------------------
	if [[ ! -f $dir/live-domains.txt ]]; then
    	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
    else
	    for domain in $(<$dir/live-domains.txt);
		do
		if [[ $(curl -ks "$domain/.bzr/README" ) =~ 'This is a Bazaar control directory.' ]]; then
		    echo -e "${RED}[$(date "+%H:%M:%S")] .git/HEAD file found @ $domain/.bzr/README${ENDCOLOR}"
		    echo "$domain/.bzr/README" | anew -q source_code.txt
		fi
		done	
	fi

	#----------------------------------------------------------------

	if [ -e "$dir/source_code.txt" ]
	then
	    var=$(cat $dir/source_code.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains exposing source code files > $target/source_code.txt${ENDCOLOR}"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No source code files found"
	fi
}

function dmarc(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking DMARC vulnerability"
	if [[ ! -f $dir/live-domains.txt ]]; then
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
	    for domain in $(<$dir/live-domains.txt);
		do
			if [[ $(curl -ks -X GET "https://dmarcly.com/server/dmarc_check.php?domain=${SITE}") =~ 'success' ]]; then
				echo -e "${RED}[$(date "+%H:%M:%S")] $domain is vulnerable to DMARC${ENDCOLOR}"
				echo "$domain" | anew -q $dir/dmarc.txt
			fi
		done	
	fi

	#--------------------------------------------------------------
	if [ -e "$dir/dmarc.txt" ]
	then
	    var=$(cat $dir/dmarc.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains are vulnerable to DMARC > $target/dmarc.txt"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} No DMARC vulnerable domains found"
	fi
}

function spf(){
	echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Checking missing SPF records"
	if [[ ! -f $dir/live-domains.txt ]]; then
	echo -e "${YELLOW}[$(date "+%H:%M:%S")] No 'live-domains.txt' found for $target${ENDCOLOR}";
	else
		for domain in $(<$dir/live-domains.txt);
		do
		    domain=$(echo $domain | sed 's,http://,,; s,https://,,;') # remove protocol from domain name
		    if [[ $(curl -ks -d "serial=fred12&domain=$domain" -H "Content-Type: application/x-www-form-urlencoded" -X POST "https://www.kitterman.com/spf/getspf3.py") =~ 'No valid SPF record found' ]]; then
		        echo -e "${RED}[$(date "+%H:%M:%S")] Missing SPF record for $domain${ENDCOLOR}"
		        echo "$domain" | anew -q $dir/spf.txt;
		    fi
		done
	fi

	#--------------------------------------------------------------
	if [ -e "$dir/spf.txt" ]
	then
	    var=$(cat $dir/spf.txt | wc -l); echo -e "${RED}[$(date "+%H:%M:%S")] $var domains have missing SPF records > $target/spf.txt${ENDCOLOR}"
	else
	    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} All domains are safe from email spoof attack"
	fi
}
