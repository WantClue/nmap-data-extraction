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
xml_file = 'scan_results.xml'
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

# Creqate the "services" table if it doesn't exist
create_services_table_query = """
CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    ip_address_id INTEGER REFERENCES ip_addresses(id) ON DELETE CASCADE,
    service_name VARCHAR(50)
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

#execute the create table queries
cursor.execute(create_ip_table_query)
cursor.execute(create_ports_table_query)
cursor.execute(create_services_table_query)
cursor.execute(create_os_table_query)


#os detection needs to be added
# will be needed to guess the os if not 100% sure it shall proceed and make the best guess

# needed to extend the database with the timestamp of the scan
cursor.execute("ALTER TABLE ip_addresses ADD COLUMN IF NOT EXISTS scan_timestamp timestamp")

# Function to determine the most probable or generalize OS
def determine_probable_os(os_matches):
    # Logic to determine the most probable or generalize OS based on the provided data
    # For example, you can choose the OS with the highest accuracy or generalize to OS family
    # Implement your logic here...
    highest_accuracy_match = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
    probable_os = highest_accuracy_match.find('osclass').get('osfamily') if highest_accuracy_match else "Unknown"
    
    return probable_os

# Iterate through hosts and extract relevant information
for host in root.findall('.//host'):
    ip_address = host.find('address[@addrtype="ipv4"]').get('addr')
    ports = []
    services = []
    

    # Extract OS information
    os_matches = host.findall('.//osmatch')
    if os_matches:
        # Determine the most probable OS or generalize the information
        probable_os = determine_probable_os(os_matches)
        cursor.execute("INSERT INTO os (ip_address_id, os) VALUES (%s, %s)", (ip_address_id, probable_os))

    for port in host.findall('.//port'):
        port_number = port.get('portid')
        service_elem = port.find('service')
        if service_elem is not None:
           service = service_elem.get('name')
        else:
           service = "Unknown"
        ports.append(port_number)
        services.append(service)

    # Insert data into the PostgreSQL database
    cursor.execute("INSERT INTO ip_addresses (ip_address, scan_timestamp) VALUES (%s, to_timestamp(%s)) ON CONFLICT (ip_address) DO NOTHING RETURNING id", (ip_address, scan_timestamp))
    ip_address_id = cursor.fetchone()

    if ip_address_id is not None:
        ip_address_id = ip_address_id[0]
    else:
        cursor.execute("SELECT id FROM ip_addresses WHERE ip_address = %s", (ip_address,))
        ip_address_id = cursor.fetchone()[0]

    for port, service in zip(ports, services):
        cursor.execute("INSERT INTO ports (ip_address_id, port_number) VALUES (%s, %s)",
                       (ip_address_id, port))
        cursor.execute("INSERT INTO services (ip_address_id,service_name) VALUES (%s, %s)",
                       (ip_address_id, service))

    conn.commit()

# Close the database connection
cursor.close()
conn.close()


