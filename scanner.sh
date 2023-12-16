#!/bin/bash

# storage of the external scan date will be stored in an external postgres database
# the database will be available at the same ip with port 5432
# usernam postgres
# password mysecretpassword
# 
# this shall be a concept of scanning the local networks for the purpose of extracting
# vulnerbilities foundable in the network
# for script usage minor issues need to be fixxed in the OS
# used is AlpineOS to have a very lightweight OS 

#color codes
RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE="\\033[38;5;27m"
SEA="\\033[38;5;49m"
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

#os
function getOS() {
  grep -E '^(VERSION|NAME)=' /etc/os-release | cut -d '"' -f2
}


if ! figlet -v > /dev/null 2>&1; then
	sudo apt-get update -y > /dev/null 2>&1
	sudo apt-get install -y figlet > /dev/null 2>&1
fi


if ! wget --version > /dev/null 2>&1 ; then
	sudo apt install -y wget > /dev/null 2>&1 && sleep 2
fi

if ! whiptail -v > /dev/null 2>&1; then
	sudo apt-get install -y whiptail > /dev/null 2>&1
fi


function setupPostgres() {
    # Use whiptail to prompt the user for PostgreSQL credentials
    POSTGRES_USER=$(whiptail --inputbox "Enter PostgreSQL username:" 10 50 3>&1 1>&2 2>&3)
    POSTGRES_PASSWORD=$(whiptail --passwordbox "Enter PostgreSQL password:" 10 50 3>&1 1>&2 2>&3)

    # Validate that the user provided a username and password
    if [ -z "$POSTGRES_USER" ] || [ -z "$POSTGRES_PASSWORD" ]; then
        echo -e "${RED}Error: Username and password are required.${NC}"
        exit 1
    fi
    
    # Create or update the docker-compose.yml file with dynamic values
    cat <<EOF >postgres-compose.yml
version: '3'

services:
  postgres:
    image: postgres:latest
    container_name: my-postgres-container
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: $POSTGRES_USER
      POSTGRES_PASSWORD: $POSTGRES_PASSWORD
    volumes:
      - postgres-data:/var/lib/postgresql/data

volumes:
  postgres-data:
EOF
}

function startPostgres() {
    #starting the postgresdb compose file
    echo -e "${GREEN}Starting PostgresDB.${NC}"
    sleep 5
    docker-compose -f postgres-compose.yml up -d
    docker ps 
    sleep 5
}

function listDatabases() {
    read -rp "Enter PostgreSQL host (default: localhost): " POSTGRES_HOST
    POSTGRES_HOST=${POSTGRES_HOST:-localhost}

    read -rp "Enter PostgreSQL port (default: 5432): " POSTGRES_PORT
    POSTGRES_PORT=${POSTGRES_PORT:-5432}

    read -rp "Enter PostgreSQL username: " POSTGRES_USER
    read -rsp "Enter PostgreSQL password: " POSTGRES_PASSWORD
    echo

    # Use psql to list databases
    databases=$(PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -l -t | cut -d'|' -f1 | sed -e '/^\s*$/d')
    
    if [ -z "$databases" ]; then
        echo -e "\nNo databases found."
        return
    fi

    # Prompt user to select a database
    PS3="Select a database: "
    select db_name in $databases; do
        if [ -n "$db_name" ]; then
            break
        else
            echo "Invalid option. Please select a valid database."
        fi
    done

    read -rp "Enter your SQL query: " sql_query

    # Use psql to run the provided SQL query on the selected database
    PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$db_name" -c "$sql_query"

    read -p "Press ENTER to continue..."
}


while true; do
    clear
    sleep 1

    echo -e "${BLUE}"
    figlet -f slant "Toolbox"
    echo -e "${YELLOW}================================================================${NC}"
    echo -e "${GREEN}OS: $(getOS) ${NC}"
    echo -e "${GREEN}Created by: WantClue${NC}"
    echo -e "${YELLOW}================================================================${NC}"
    echo -e "${CYAN}1  - Setup PostgresDB${NC}"
    echo -e "${CYAN}2  - Run PostgresDB Container${NC}"
    echo -e "${CYAN}3  - Database query${NC}"
    echo -e "${CYAN}4  - Abort${NC}"
    echo -e "${YELLOW}================================================================${NC}"


    read -rp "Pick an option and hit ENTER: "
    case "$REPLY" in
     1)  
    		clear
    		sleep 1
    		setupPostgres
     ;;
     2) 
     		clear
    		sleep 1
    		startPostgres
     ;;
    3) 
    		clear
    		sleep 1
    		listDatabases
     ;;
     4) 
    		clear
    		sleep 1
    		exit
     ;;
    esac
done