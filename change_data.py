import xml.etree.ElementTree as ET
import psycopg2
from psycopg2 import extensions

#Define your PostgreSQL database connection parameters
db_params = {
    'user': 'postgres',
    'password': 'mysecretpassword',
    'host': '10.0.10.43',
    'port': '5432',
}

#change of the database entries information and security if needed
#maybe information that should be added as notes
