#!/bin/bash

###### Configuration #########
#Gateway IP
_gwIP=192.168.0.254 
#Gateway name
_gwName=my_gateway
#Workstation name 
_wsName=my_workstation
#Internal network name
_intNW=docker_internal
#Persistence (true/false)
persistence=true

#####Output Colors#############
white="\033[1;37m"
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
blue="\033[1;34m"
transparent="\e[0m"

########################################
### ANONYMIZING MIDDLEBOX SETTINGS######
# These settings are pushed to the torrc of the gateway container.

_torSettings="VirtualAddrNetworkIPv4 10.192.0.0/10
Log notice file /root/.tor/notices.log
DataDirectory /root/.tor
Log notice stdout
SocksPort $_gwIP:9050
ControlPort $_gwIP:9051
CookieAuthentication 1
HashedControlPassword 16:0430F4846DCB79EB605DAB188CF619860A18B86C20D075B84CB97E0695
AutomapHostsOnResolve 1
TransPort $_gwIP:9040 
DNSPort $_gwIP:53"
#########################################


########## Functions ####################

function cleanup {
printf "\n%b\n" "Clean up everything..."
docker exec -it -d -e USER=root $_wsID su -c "vncserver -kill :2" root
printf "%s\n" "Removing the containers..." 
echo "$(docker stop $_gwID $_wsID)"
#docker rm $(docker ps -a -q)
rm log 2> /dev/null
printf "\n$white%b$transparent\n" "Bye bye.."
sleep 2

}


##	Is Docker Daemon running?
docker ps > /dev/null
if [ $? -ne 0 ]; then
	printf "\n$red%s$transparent\n\n" "[Docker daemon not running or permission denied...]"
	exit 1
fi

#If there are any stopped containers, delete them
if [ "$(docker ps -a | grep "$_gwName\|$_wsName")" != "" ]; then
	printf "\n$yellow%s$transparent\n" "[Found previously used Containers - deleting...]"
	docker stop $(docker ps -a | grep "$_gwName\|$_wsName" | awk '{ print$1 }') > /dev/null
	docker rm $(docker ps -a | grep "$_gwName\|$_wsName" | awk '{ print$1 }') > /dev/null
fi
rm log 2> /dev/null

########## Start a Containainer from the Gateway Image ##########

printf "\n$white%s$transparent\n" "Starting a Gateway Container..."
_gwID=$(docker run -it --rm --privileged -d $_gwName) 

if [ "$_gwID" != "" ]; then
	printf "%s\n" "Container started with ID: $_gwID"
	printf "$green%s$transparent\n" "[Success!]"
else
	printf "\n$red%s$transparent\n" "[Error getting Container ID. See above errors!]"
	exit 1
fi

########### Connect Container to internal Network ################

printf "\n$white%s$transparent\n" "Connecting internal Network..."
docker network connect --ip $_gwIP $_intNW $_gwID
if [ $? -ne 0  ]; then
	exit 1
fi
printf "$green%s$transparent\n" "[Success!]"

########## Start Tor in Container ##########

printf "\n$white%s$transparent\n" "Starting Tor within our newly created Container..."
docker exec -it -d $_gwID sh -c "echo '$_torSettings' >> /etc/tor/torrc"
docker exec -it -d $_gwID sh -c "pkill tor"
docker exec -it -d $_gwID sh -c "tor > log"
sleep 2
test="test"
declare -i timeout
declare -i try
timeout=0
try=0

function checkconnection {
while [ "$test" !=  "100%" ]
do
	docker exec -it $_gwID /bin/sh -c "cat log" >> log
	test=$(tail -n1 log | awk '{ print $6 }' | cut -d':' -f1)
	printf "\033[K%s\r" "Connection Status: $test"
	sleep 1
	timeout+=1
	if [ $timeout -eq 20 ]; then
		printf "$yellow%s$transparent\n" "[Connection timeout. Retry..]"
		try+=1
		docker exec -it -d $_gwID /bin/sh -c "pkill tor"
	        sleep 2
		docker exec -it -d $_gwID sh -c "tor > log"
		sleep 2
		timeout=0
	fi
done
}
checkconnection
printf "$green%s$transparent\n" "[Success!]"

########## IPTABLES RULES ###########

printf "\n$white%s$transparent\n" "Applying iptables rules..."
#TransPort
_trans_port="9040"
#internal interface name
_inc_if="eth1"
# exlude from Tor
_NON_TOR="192.168.0.0/24 172.18.0.0/16"
docker exec -it $_gwID sh -c "iptables -F"
docker exec -it $_gwID sh -c "iptables -t nat -F"
for NET in $NON_TOR; do
 	docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -d $NET -j RETURN"
done
docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -p udp --dport 53 -j REDIRECT --to-ports 53"
docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -p udp --dport 5353 -j REDIRECT --to-ports 53"
docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -p tcp --syn -j REDIRECT --to-ports $_trans_port"
printf "$green%s$transparent\n" "[Success!]"


########## Start Workstation Container ##############

printf "\n$white%s$transparent\n" "Starting a Workstaion Container..."

if [ "$persistence" = "true" ]; then
	printf "$blue%s$transparent\n" "Persistence is enabled, mounting local storage."
	_wsID=$(docker run -it --rm --privileged --mount src=kali-root,dst=/root --net=docker_internal -e USER=root -d $_wsName)
else
	printf "$yellow%s$transparent\n" "Persistence is disabled, not mounting local storage."
	_wsID=$(docker run -it --rm --privileged --net=docker_internal -e USER=root -d $_wsName)
fi

if [ $? -ne 0 ]; then
	printf "\n$red%s$transparent\n" "[Error starting Workstation - is the name correct?]"
	exit 1
fi

## Get the IP of the newly created Container
_wsIP=$(docker exec -it $_wsID sh -c "ip a | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'")
echo "ID: $_wsID"
echo "IP: $_wsIP"
printf "$green%s$transparent\n" "[Success!]"


########## Set the gateway container as the workstation's default gateway ##########
printf "\n$white%s$transparent\n" "Setting default gateway of workstation..."
docker exec -it -d $_wsID sh -c "ip route del default"
docker exec -it -d $_wsID sh -c "ip route add default via $_gwIP"

## Check Gateway
_chkgwIP=$(docker exec -it $_wsID sh -c "ip route | head -n1 ") 
_chkgwIP=$(echo $_chkgwIP | awk '{ print $3 }')

if [[ "$_chkgwIP" = "$_gwIP" ]]; then
	printf "$green%s$transparent\n" "[Success!]"
else
	printf "$red%s$transparent\n" "[Error setting the default gateway... ]"
	echo $_chkgwIP
	exit 1
fi



########## Checking IP ###########
function checkip {
printf "\n$white%s$transparent\n" "Checking connection..."
_torip=$(docker exec -it $_wsID sh -c "curl --silent https://canihazip.com/s")
_clearip=$(curl --silent https://canihazip.com/s)

## Check clear net IP ##
if [[ $_clearip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf "%s\n" "Host IP: $_clearip"        
else
        printf "$red%s$transparent" "[Error. Do we have an Internet connection?]"
        echo $_clearip
        cleanup
        exit 1
fi

## Check public Container IP ##
if [[ $_torip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	
	if [ "$_clearip" != "$_torip" ]; then
		printf "%s\n" "Workstation IP: $_torip"
		printf "$green%s$transparent\n" "[Success!]"
	else	
		printf "$red%s$transparent\n" "[Worstation has your clearnet IP!]"
		cleanup
		exit 1
	fi
else
	printf "$red%s$transparent" "[Error getting an IP Adress!]"
    echo $_torip
	cleanup
	exit 1
fi
sleep 2
}
checkip
############### MENU ########################
revisit=0

function menu {
	clear
	
	printf "\n\n$white%s$transparent\n\n" "What shall we do next?" 
	printf "%s\t$white%s\t%s$transparent\n" "[Workstation]" "Start a Terminal Session" "(t)"
	printf "%s\t$white%s\t\t%s$transparent\n" "[Workstation]" "Start a VNC Session" "(v)"
	printf "%s\t$white%s\t%s$transparent\n" "[Gateway]" "Start a Terminal Session" "(g)" 
	printf "%s\t$white%s\t\t\t%s$transparent\n" "[System]" "New Identity" "(n)"
	printf "%s\t$white%s\t\t%s$transparent\n" "[System]" "Check Connection" "(c)"
	printf "%s\t$white%s\t\t%s$transparent\n" "[System]" "Quit and clean up" "(q)" 


}

	while [ "$choice" != "q" ]
	do
		menu
		printf "\n\n%s" ""
		printf "%s" "Enter: "
		read choice
			## Connect to work station terminal
			if [ "$choice" = "t" ]; then
				clear
				printf "\n$white%s$transparent\n" "Connecting to Workstation Terminal.. (type 'exit' to return to menu)"
	        		sleep 1
				docker exec -it -e USER=root $_wsID /bin/bash
			        
			fi
			## Start and connect workstation VNC
			if [ "$choice" = "v" ]; then
				clear
				printf "\n$white%s$transparent\n" "Starting VNC Server in Workstation... (close vncviewer to return to menu)"
	        	sleep 1
				_checkvnc=$(docker exec -it -e USER=root $_wsID bash -c "ps -e | grep Xtightvnc")
				
				if [ "$_checkvnc" = "" ]; then
					#docker exec -it -e USER=root $_wsID vncpasswd
					docker exec -it -e USER=root $_wsID su -c "vncserver :2" root
				fi
				## We start the vncviewer in a seperate xterm because theres no way to run it in the background
				xterm -e "vncviewer $_wsIP:2" &
				
				#docker exec -it -e USER=root $_wsID su -c "vncserver -kill :2" root
			        
			fi
			## Check Connection
			if [ "$choice" = "c" ]; then
				printf "\n%s" ""
				checkip
				printf "\n%s" "Press any key..."
				read p
			fi
			
			## New identity via ControlPort
			if [ "$choice" = "n" ]; then
				printf "\n$white%s$transparent\n" "Getting new identity..."
				docker exec -it $_gwID sh -c "(echo authenticate '""'; echo signal newnym; echo quit) | nc $_gwIP 9051"
				checkip
				printf "\n%s" "Press any key..."
				read p
			fi
			
			
			## connect to gateway terminal
			if [ "$choice" = "g" ]; then
				clear
				printf "\n$white%s$transparent\n" "Connecting to Gateway Terminal.. (type 'exit' to return to menu)"
	        		sleep 1
				docker exec -it -e USER=root $_gwID /bin/sh
			        
			fi

	
	done




cleanup
exit 0
