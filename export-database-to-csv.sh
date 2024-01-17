#!/bin/bash

# Variables
HOSTNAME='your_hostname'
DATABASE='your_database_name'
USERNAME='your_username'
PASSWORD='your_password'
EXPORT_PATH='/path/to/export' # make sure this directory exists

# Export each table
for TABLE in `psql -h $HOSTNAME -d $DATABASE -U $USERNAME -t -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public';"`
do
    echo "Exporting $TABLE"
    PGPASSWORD=$PASSWORD psql -h $HOSTNAME -d $DATABASE -U $USERNAME -c "\COPY (SELECT * FROM $TABLE) TO '$EXPORT_PATH/$TABLE.csv' WITH CSV HEADER"
done
