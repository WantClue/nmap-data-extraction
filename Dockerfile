# Use a base image that includes a Linux distribution
FROM alpine:latest

# Install Nmap
RUN apk update && apk add python3 py3-psycopg2 libxml2-utils nmap

# Copy your scanning script into the container
COPY insert.py /app/insert_data_into_postgres.py
COPY scan_result_1.xml /app/scan_results.xml

# Set the entry point to run your Python script
ENTRYPOINT ["python3", "/app/insert_data_into_postgres.py"]

# Set the working directory
WORKDIR /app
