# NMAP XML to PostgreSQL Database Importer

## This is a proof of concept for extract Data from an nmap scan into a postgresDB

I recently came up with the idea of having a relative database to show me all information about a network and all it's connected machines. Therefore I would need to have the ability to link ip addresses with it's relative data e.g. {ports,services,os detections...} u name it.

This current iteration will hopefully help you to verify whats going on in your network and the future plan is to have an overview maybe even visual to locate potential issues or threaths in your network.

## Overview

### 1. Database Initialization:

Connects to a PostgreSQL database server using the specified parameters.
Checks if a database with a unique name based on the scan timestamp already exists.
If the database does not exist, it is created. Otherwise, the script aborts.

### 2. Table Creation:

Defines and creates the necessary tables in the PostgreSQL database to store IP addresses, ports, services, operating systems, timestamps, CVEs (Common Vulnerabilities and Exposures), and associations between services and CVEs.

### 3. Data Extraction and Insertion:

Iterates through the hosts and extracts information such as IP addresses, ports, services, operating system details, and CVEs from the Nmap XML file.
Inserts the extracted data into the corresponding tables in the PostgreSQL database.
Handles cases where a record with the same IP address or port already exists, preventing duplicate entries.

### 4. Association of CVEs with Services:

Associates CVEs with services by creating entries in the service_cve table.
Checks if a CVE entry already exists in the cve table. If not, a new entry is created.

# Environment

This is currently designed to work on an Ubuntu LXC container.
You could run this in every environment that you preffer I just like the fact of playing with Container, the future plan is to have a Docker-compose to have everything in one environment.

# Requirements

To work properly with my intention of having the ability to see current CVEs and probably vulnerbilities I installed and use the script vulners [Vulners github](https://github.com/vulnersCom/nmap-vulners).

Clone the vulners repo onto the machine to be able to use the script functionallity.

- Python 3.x
- psycopg2 library (for PostgreSQL connectivity)
- A PostgreSQL database server with appropriate privileges

# How to run this script

Ensure that you do have the required Python libraries installed: `pip install psycopg2`

Currently I do run a nmap scan with the following arguments `nmap -p 1-25000 -sV --scrip vulners -O -oX scan_results.xml --reason ip-address-range`

You need to change the database ip and password aswell as the username to connect to your personal postgresDB in order to function correctly

# Example nmap scan

To have an xml file that would be able to be read by this python parser this is some example I used to get the appropiate results
Keep in mind that you need to change the ip range you want to change appropiate.

```
nmap -p 1-25000 --script vulners -O -sV -oX scan_result.xml --reason 10.0.10.0/24
```

# Example usecases for the postgresDb

These are examples to get the ip_addresses, ports, service_names fora specific ip address e.g. 10.0.10.5. Change thise ip address according to your device you wanna get information about.

```
SELECT
    ip_addresses.ip_address,
    ports.port_number,
    services.service_name,
    info.info_id
FROM
    ip_addresses
LEFT JOIN ports ON ip_addresses.id = ports.ip_address_id
LEFT JOIN services ON ports.id = services.port_id
LEFT JOIN info ON services.id = info.service_id
WHERE
    ip_addresses.ip_address = '10.0.10.5'
ORDER BY
    ports.port_number;
```

```
SELECT
    ip_addresses.ip_address,
    ports.port_number,
    services.service_name,
    info.info_id,
    cve.cve_id,
    cve.cvss
FROM
    ip_addresses
LEFT JOIN ports ON ip_addresses.id = ports.ip_address_id
LEFT JOIN services ON ports.id = services.port_id
LEFT JOIN info ON services.id = info.service_id
LEFT JOIN service_cve ON services.id = service_cve.service_id
LEFT JOIN cve ON service_cve.cve_id = cve.id
WHERE
    ip_addresses.ip_address = '10.0.10.19'
ORDER BY
    ports.port_number;
```

# Notes

- The script assumes a specific structure in the Nmap XML file, and any deviations may require adjustments in the code.
- Ensure that the PostgreSQL server is running and accessible with the provided credentials.
- The script uses unique constraints and conflict resolution to avoid duplicate entries in the database.

# Roadmap

- [x] Basic functionallity of extracting data
- [x] Setup a Docker compose to simulate a Network with different machines
- [ ] Add a script to be more user friendly (will add in functions to select ranges and more)

## Disclaimer

This script is provided as-is, and the user is responsible for understanding and adapting it to their specific use case. Use caution when working with production databases, and always have backups in place.

---

# SNMP network client data extraction

The idea of the snmp client data extraction is to have another reliable source to verify the data and expand the knowledge about the devices we do have in our network. This requieres obviously network access and access to the remote devices. In this example we will use the Net-SNMP package

## Links

[Net-SNMP](http://www.net-snmp.org/)

# Installation

## Debian based systems

` sudo apt-get install snmp snmpd`

## For Windows

SNMP is included in Windows features. You can enable it through the Control Panel.

# You like my Work? Support me!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R0IYN9V)
