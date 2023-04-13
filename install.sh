#!/bin/bash

# Usage: sudo ./install.sh
# prerequisite: Python & Go : https://github.com/udhos/update-golang
# mv nuclei-templates /path/to/new/location/
# Export NUCLEI_TEMPLATES_PATH=/path/to/new/location/nuclei-templates
# echo $NUCLEI_TEMPLATES_PATH
# Keep manually updating nuclei templates


RED="\e[31m"
GREEN="\e[32m"
YELLOW="\033[0;33m"
ENDCOLOR="\e[0m"

function dependencies_1(){
    sudo apt-get -qq install -y libpcap-dev
    sudo apt-get install -y python-pip
    sudo apt-get install -y python3-pip
    pip install -q selenium webdriver-manager
}

function scripts_download(){
    function fgds(){
        #FGDS
        if [ -e FGDS.sh ]; then
          echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} FGDS.sh already exists in the current directory";
        else
          wget -q https://raw.githubusercontent.com/IvanGlinkin/Fast-Google-Dorks-Scan/master/FGDS.sh;
          sudo chmod +x FGDS.sh;
          echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} FGDS.sh installed in $(pwd)";
        fi
    }
    fgds

    function get-title(){
        #Get-title
        if [ -e get-title ]; then
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} get-title already exists in the current directory";
        else
            mkdir -p ./temp
            cd ./temp
            wget -q https://raw.githubusercontent.com/tomnomnom/hacks/master/get-title/main.go
            go mod init mymodule > /dev/null 2>&1
            go get github.com/tomnomnom/gahttp
            go get golang.org/x/net/html
            go build -o ../get-title main.go
            cd ..
            rm -r ./temp
            sudo cp get-title /usr/local/bin
          echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} get-title installed in $(pwd)";
        fi
    }
    get-title

    function anti-burl(){
        #Anti-burl
        if [ -e anti-burl ]; then
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} anti-burl already exists in the current directory";
        else
            mkdir -p ./temp
            cd ./temp
            wget -q https://raw.githubusercontent.com/tomnomnom/hacks/master/anti-burl/main.go
            go build -o ../anti-burl main.go
            cd ..
            rm -r ./temp
            sudo cp anti-burl /usr/local/bin
          echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Anti-burl installed in $(pwd)";
        fi
    }
    anti-burl

    # TestSSL
    function testssl(){
        #Anti-burl
        if [ -e testssl/testssl.sh ]; then
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} testssl.sh already exists in the ./testssl directory";
        else
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} testssl.sh not installed. So installing in $(pwd)/testssl";
            git clone --quiet --depth 1 https://github.com/drwetter/testssl.sh.git
            mv testssl.sh testssl
            chmod +x testssl/testssl.sh
            sudo apt-get install -y bsdmainutils
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} testssl.sh installed in $(pwd)/testssl";
        fi
    }
    testssl
}

function goinstall(){ 
    cd ~/go/bin
    echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Installing Required Golang Tools";

    check_install() {
        # Check if the tool is already installed
        if [ -x "$(command -v $1)" ]; then
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $1 Already Exists";
        else
            echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} Installing $1";

            # Try to install the tool
            go install -v $2@latest >> /dev/null;
            
            # Check if the installation was successful
            if [ -x "$(command -v $1)" ]; then
              echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $1 Installed";
            elif [ -x "$HOME/go/bin/$1" ]; then
              echo -e "${YELLOW}[$(date "+%H:%M:%S")]${ENDCOLOR} $1 is installed in ~/go/bin directory";
              sudo cp $HOME/go/bin/$1 /usr/local/bin/
              echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} $1 installed to /usr/local/bin/";
            else
              echo -e "${RED}[$(date "+%H:%M:%S")]${ENDCOLOR} Failed to install $1";
            fi
        fi
    }

    check_install "unfurl" "github.com/tomnomnom/unfurl"
    check_install "burl" "github.com/tomnomnom/burl"
    check_install "httprobe" "github.com/tomnomnom/httprobe"
    check_install "anew" "github.com/tomnomnom/anew"
    check_install "katana" "github.com/projectdiscovery/katana/cmd/katana"
    check_install "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    check_install "meg" "github.com/tomnomnom/meg"
    check_install "getJS" "github.com/003random/getJS"
    check_install "assetfinder" "github.com/tomnomnom/assetfinder"
    check_install "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
    check_install "waybackrobots" "github.com/vodafon/waybackrobots"
    check_install "ffuf" "github.com/ffuf/ffuf"
    check_install "qsreplace" "github.com/tomnomnom/qsreplace"
    check_install "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    check_install "subzy" "github.com/LukaSikic/subzy"
    check_install "cero" "github.com/glebarez/cero"
    check_install "hakrawler" "github.com/hakluke/hakrawler"
    check_install "concurl" "github.com/tomnomnom/concurl"
    check_install "gau" "github.com/lc/gau/v2/cmd/gau"
    check_install "waybackurls" "github.com/tomnomnom/waybackurls"
    check_install "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
}

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

            echo -e "${YELLOW}[$(date "+%H:%M:%S")] Nuclei-template directory already exists and is not empty${ENDCOLOR}";
            echo -e "${YELLOW}[$(date "+%H:%M:%S")] Check if it contains nuclei-templates or not while tool is busy in other thing${ENDCOLOR}";
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

function dependencies_2(){
    #Nmap
    sudo apt install nmap -y
}

function files_check(){
        if [ -e "./discoverylist.txt" ]; then
          echo -e "${GREEN}[$(date "+%H:%M:%S")]${ENDCOLOR} discoverylist.txt exists in the current directory";
        else
          echo -e "${RED}[$(date "+%H:%M:%S")] discoverylist.txt does not exist in current directory${ENDCOLOR}";
          exit 1
        fi
}
