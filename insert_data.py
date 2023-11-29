import xml.etree.ElementTree as ET
import psycopg2
from psycopg2 import extensions
from datetime import datetime


#Define your PostgreSQL database connection parameters
db_params = {
    'user': 'postgres',
    'password': 'mysecretpassword',
    'host': '10.0.10.43',
    'port': '5432',
}

# Establish a connection to the PostgreSQL database
initial_conn = psycopg2.connect(**db_params)
initial_cursor = initial_conn.cursor()

# Parse the Nmap scan result XML file
xml_file = 'test2.xml'
tree = ET.parse(xml_file)
root = tree.getroot()
# extract the timestamp
scan_timestamp = root.get('start')

# Generate a unique database name based on the scan timestamp
database_name = f'scan_{scan_timestamp.replace(" ", "_").replace(":", "_")}'
print(f'Creating database: {database_name}')

# Check if the database already exists
initial_cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (database_name,))
database_exists = initial_cursor.fetchone()

if not database_exists:
    #close initial connection
    initial_cursor.close()
    initial_conn.close()

    #set the isolation lvl
    auto_commit = extensions.ISOLATION_LEVEL_AUTOCOMMIT

    #connect to default db
    initial_conn = psycopg2.connect(database='postgres', **db_params)
    initial_conn.set_isolation_level(auto_commit)
    initial_cursor = initial_conn.cursor()

    # Create the new database
    initial_cursor.execute(f'CREATE DATABASE {database_name};')
    print(f'Database created: {database_name}')

else:
    print(f'Database {database_name} already exists. Aborting.')
    # Close the initial connection
    initial_cursor.close()
    initial_conn.close()
    exit()

# Connect to the newly created database
db_params['database'] = database_name
conn = psycopg2.connect(**db_params)
cursor = conn.cursor()


# Create the "ip_addresses" table if it doesn't exist
create_ip_table_query = """
CREATE TABLE IF NOT EXISTS ip_addresses (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(15) UNIQUE NOT NULL
);
"""

# Create the "ports" table if it doesn't exist
create_ports_table_query = """
CREATE TABLE IF NOT EXISTS ports (
    id SERIAL PRIMARY KEY,
    ip_address_id INTEGER REFERENCES ip_addresses(id) ON DELETE CASCADE,
    port_number INTEGER
);
"""

# Add unique constraint to the ports table
add_ports_unique_constraint_query = """
ALTER TABLE ports
ADD CONSTRAINT ports_unique_constraint UNIQUE (ip_address_id, port_number);
"""

# Creqate the "services" table if it doesn't exist
create_services_table_query = """
CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    ip_address_id INTEGER REFERENCES ip_addresses(id) ON DELETE CASCADE,
    port_id INTEGER REFERENCES ports(id) ON DELETE CASCADE,
    service_name VARCHAR(50),
    CONSTRAINT services_unique_constraint UNIQUE (ip_address_id, port_id, service_name)
);
"""

# Create table for the OS version that has been guessed
create_os_table_query = """
CREATE TABLE IF NOT EXISTS os (
    id SERIAL PRIMARY KEY,
    ip_address_id INTEGER REFERENCES ip_addresses(id) ON DELETE CASCADE,
    os VARCHAR(50)
);
"""

# Create table for the OS version that has been guessed
create_timestamp_table_query = """
CREATE TABLE IF NOT EXISTS timestamp (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP
);
"""

create_cve_table_query = """
CREATE TABLE IF NOT EXISTS cve (
    id SERIAL PRIMARY KEY,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    cvss VARCHAR(255)
);    
"""

create_cve_service_table_query = """
CREATE TABLE IF NOT EXISTS service_cve (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(15) NOT NULL,
    port_number INTEGER NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cve(id) ON DELETE CASCADE
);
"""

create_info_table_query = """
CREATE TABLE IF NOT EXISTS info (
    id SERIAL PRIMARY KEY,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    info_id VARCHAR(50) NOT NULL
)
"""
#execute the create table queries
cursor.execute(create_ip_table_query)
cursor.execute(create_ports_table_query)
cursor.execute(add_ports_unique_constraint_query)
cursor.execute(create_services_table_query)
cursor.execute(create_os_table_query)
cursor.execute(create_timestamp_table_query)
cursor.execute(create_cve_table_query)
cursor.execute(create_cve_service_table_query)
cursor.execute(create_info_table_query)


# Function to determine the most probable or generalize OS
def determine_probable_os(os_matches):
    # Logic to determine the most probable or generalize OS based on the provided data
    # For example, it can choose the OS with the highest accuracy or generalize to OS family
    highest_accuracy_match = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
    probable_os = highest_accuracy_match.find('osclass').get('osfamily') if highest_accuracy_match else "Unknown"
    
    return probable_os

# Iterate through hosts and extract relevant information
for host in root.findall('.//host'):
    ip_address = host.find('address[@addrtype="ipv4"]').get('addr')
    ports = []
    services = []

    # Insert data into the PostgreSQL database
    cursor.execute("INSERT INTO ip_addresses (ip_address) VALUES (%s) ON CONFLICT (ip_address) DO NOTHING RETURNING id", (ip_address,))
    cursor.execute("INSERT INTO timestamp (timestamp) VALUES (to_timestamp(%s)) RETURNING id", (scan_timestamp,))
    ip_address_id = cursor.fetchone()

    if ip_address_id is not None:
        ip_address_id = ip_address_id[0]
    else:
        cursor.execute("SELECT id FROM ip_addresses WHERE ip_address = %s", (ip_address,))
        ip_address_id = cursor.fetchone()[0]

    # Extract OS information
    os_matches = host.findall('.//osmatch')
    if os_matches:
        # Determine the most probable OS or generalize the information
        probable_os = determine_probable_os(os_matches)
        cursor.execute("INSERT INTO os (ip_address_id, os) VALUES (%s, %s)", (ip_address_id, probable_os))

    for port in host.findall('.//port'):
        port_number = port.get('portid')

	# Extract service information
        service_elem = port.find('service')

        if service_elem is not None:
            service = service_elem.get('name')
            version = service_elem.get('version')

            # Debugging prints
            print(f"Service: {service}, Version: {version}")    

            # Insert port into the database
            cursor.execute("INSERT INTO ports (ip_address_id, port_number) VALUES (%s, %s) ON CONFLICT (ip_address_id, port_number) DO NOTHING", (ip_address_id, port_number))
            cursor.execute("SELECT id FROM ports WHERE ip_address_id = %s AND port_number = %s", (ip_address_id, port_number))
            port_id = cursor.fetchone()[0]

            # Insert service into the database
            cursor.execute("INSERT INTO services (ip_address_id, port_id, service_name) VALUES (%s, %s, %s) ON CONFLICT (ip_address_id, port_id, service_name) DO NOTHING RETURNING id", (ip_address_id, port_id, service))
            service_id = cursor.fetchone()[0]

            # Insert version into the database
            cursor.execute("INSERT INTO info (service_id, info_id) VALUES (%s, %s)", (service_id, f"Version: {version}"))

            # Check if there is CVE information for the service
            for table in port.findall('.//table'):
                elem_type = table.find('elem[@key="type"]')
                elem_text = table.find('elem[@key="id"]')
                if elem_type is not None and elem_text is not None and elem_type.text == "cve":
                    cve_id = elem_text.text
                    cvss_elem = table.find('elem[@key="cvss"]')
                    cvss = cvss_elem.text if cvss_elem is not None else None

                    # Check if the CVE entry already exists in the database
                    cursor.execute("SELECT id FROM cve WHERE cve_id = %s", (cve_id,))
                    cve_entry = cursor.fetchone()

                    if not cve_entry:
                        # If the CVE entry doesn't exist, insert a new row into the cve table
                        cursor.execute("INSERT INTO cve (cve_id, cvss) VALUES (%s, %s) RETURNING id", (cve_id, cvss))
                        new_cve_id = cursor.fetchone()[0]

                        # Associate the new CVE entry with the service
                        cursor.execute("INSERT INTO service_cve (ip_address, port_number, service_name, service_id, cve_id) VALUES (%s, %s, %s, %s, %s)",
                           (ip_address, port_number, service, service_id, new_cve_id))

            

        else:
            # If no service name or version, insert as "Unknown"
            cursor.execute("INSERT INTO ports (ip_address_id, port_number) VALUES (%s, %s) RETURNING id", (ip_address_id, port_number))
            port_id = cursor.fetchone()[0]

            cursor.execute("INSERT INTO services (ip_address_id, port_id, service_name) VALUES (%s, %s, %s) RETURNING id", (ip_address_id, port_id, "Unknown"))
            service_id = cursor.fetchone()[0]

            cursor.execute("INSERT INTO info (service_id, info_id) VALUES (%s, %s)", (service_id, "Version: Unknown"))
    
    conn.commit()

# Close the database connection
cursor.close()
conn.close()