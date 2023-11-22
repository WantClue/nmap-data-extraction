import psycopg2
import subprocess

# PostgreSQL database connection parameters
db_params = {
    'host': '10.0.10.43',
    'port': '5432',
    'user': 'postgres',
    'password': 'mysecretpassword',
    'database': 'nmap_commands',
}

# Connect to the PostgreSQL database
try:
    connection = psycopg2.connect(**db_params)
    cursor = connection.cursor()

    # Retrieve the Nmap command from the database
    cursor.execute("SELECT nmap_command FROM commands WHERE id=1;")
    nmap_command = cursor.fetchone()[0]  # Assuming there's only one result

    # Execute the Nmap command using subprocess
    subprocess.run(nmap_command, shell=True)

except psycopg2.Error as e:
    print("Error connecting to the database:", e)

finally:
    # Close the database connection
    if connection:
        connection.close()
        print("Database connection closed.")
