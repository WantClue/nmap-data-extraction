# This is a proof of concept for extract Data from an nmap scan into a postgresDB

I recently came up with the idea of having a relative database to show me all information about a network and all it's connected machines. Therefore I would need to have the ability to link ip addresses with it's relative data e.g. {ports,services,os detections...} u name it.

This current iteration will hopefully help you to verify whats going on in your network and the future plan is to have an overview maybe even visual to locate potential issues or threaths in your network.

# Environment

This is currently designed to work inside a docker container which will perform a nmap scan with a couple of arguments and then extract the data from a xml file created while scanning.

You could run this in every environment that you preffer I just like the fact of playing with Docker to have a system that is usable in every cenario without limitations.

# How to run this script

Currently I do run a nmap scan with the following arguments {nmap -p 1-25000 -traceroute -O -oX scan_results.xml --reason ip-address-range}

You need to change the database ip and password aswell as the username to connect to your personal postgresDB in order to function correctly

# Roadmap

- [x] Basic functionallity of extracting data
- [ ] Setup a Docker compose to simulate a Network with different machines
- [ ] Add a script to be more user friendly

# You like my Work? Support me!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R5R0IYN9V)
