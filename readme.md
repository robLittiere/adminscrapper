# Adminscrapper

## What is it ?
Adminscrapper is a very simple scrapping tool made to scan devices on a network and to retreive informations about them

## What informations does it currently gather ?
For now, it only gathers easy things such as MAC address, IP address, it checks if the device was previously online, if it isn't anymore.
I also use it to know if my websites are up or down as the script makes http requests to those IP addresses.

## Where can I check the collected data
In order to check the collected data, go to the "data" subfolder. There you will find the network.json file which contains pretty much everything about the scan.
Also you will find one folder for each scanned device. These will be useful to store persistent data that we could obtain with later patches.

## How to use it ?
Download or clone the project. Launch the script using python3. Check out the data created in the data folder.
If you would like to make sure your web servers are serving pages and are not down, add the name and address of your server in the list-ips.txt file separated by a "-".
For exemple add : Nextcloud-http://192.168.100.200/nextcloud/index.php/login

