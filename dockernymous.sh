#!/bin/bash

## SET Gateway IP & Image Name
_gwIP=192.168.0.254
_gwName=deb_gw

########################################
white="\033[1;37m"
grey="\033[0;37m"
purple="\033[0;35m"
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
Purple="\033[0;35m"
Cyan="\033[0;36m"
Cafe="\033[0;33m"
Fiuscha="\033[0;35m"
blue="\033[1;34m"
transparent="\e[0m"


########################################
# ANONYMIZING MIDDLEBOX SETTINGS
_torSettings="VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040 
TransListenAddress $_gwIP
DNSPort 53 
DNSListenAddress $_gwIP"
#########################################


## Internal Network
_intNW=docker_internal
## Cleanup
docker stop $(docker ps -qa) > /dev/null
rm log

########## Start a Containainer from the Gateway Image ##########

printf "\n$white%s$transparent\n" "Starting a Gateway Container..."
_gwID=$(docker run -it --rm --privileged -d $_gwName)
echo "ID: $_gwID"
echo -e "$green[Success]$transparent"


########### Connect Container to internal Network ##########

printf "\n$white%s$transparent\n" "Connecting internal Network..."
docker network connect --ip $_gwIP $_intNW $_gwID
if [ $? -ne 0  ]; then
	exit 1
fi
echo -e "$green[Success]$transparent"


########## Start Tor in Container ##########

 printf "\n$white%s$transparent\n" "Starting Tor within our newly created Container..."
docker exec -it -d $_gwID sh -c "echo '$_torSettings' >> /etc/tor/torrc"
docker exec -it -d $_gwID pkill tor
sleep 1
docker exec -t -d $_gwID sh -c "tor > log"
sleep 2
test="test"
while [ "$test" !=  "100%" ]
do
	docker exec -it $_gwID bash -c "cat log" >> log
	test=$(tail -n1 log | awk '{ print $6 }' | cut -d':' -f1)
	printf "%s\r" "Connection Status: $test"
	sleep 0.5
done
printf "\n$green%s$transparent\n" "[Success]"


########## IPTABLES RULES ###########

printf "\n$white%s$transparent\n" "Applying iptables rules..."
#TransPort
_trans_port="9040"
#internal interface name
_inc_if="eth1"
# exlude from Tor
_NON_TOR="192.168.0.0/24"
docker exec -it $_gwID bash -c "iptables -F"
docker exec -it $_gwID bash -c "iptables -t nat -F"
for NET in $NON_TOR; do
 	docker exec -it $_gwID bash -c "iptables -t nat -A PREROUTING -i $_inc_if -d $NET -j RETURN"
done
docker exec -it $_gwID bash -c "iptables -t nat -A PREROUTING -i $_inc_if -p udp --dport 53 -j REDIRECT --to-ports 53"
docker exec -it $_gwID bash -c "iptables -t nat -A PREROUTING -i $_inc_if -p udp --dport 5353 -j REDIRECT --to-ports 53"
docker exec -it $_gwID bash -c "iptables -t nat -A PREROUTING -i $_inc_if -p tcp --syn -j REDIRECT --to-ports $_trans_port"
echo -e "$green[Success]$transparent"


########## Start Workstation Container ##############

printf "\n$white%s$transparent\n" "Starting a Workstaion Container..."
_wsID=$(docker run -it --rm --privileged --net=docker_internal -e USER=root -d kali_ws)

## Get the IP of the newly created Container
_wsIP=$(docker exec -it $_wsID bash -c "ip a | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'")
echo "ID: $_wsID"
echo "IP: $_wsIP"
echo -e "$green[Success]$transparent"


########## Set the gateway container as it's default gateway ##########

 printf "\n$white%s$transparent\n" "Setting default gateway..."
docker exec -it -d $_wsID ip route del default
docker exec -it -d $_wsID ip route add default via $_gwIP

## Check Gateway
_chkgwIP=$(docker exec -it $_wsID bash -c "ip route | head -n1 ") 
_chkgwIP=$(echo $_chkgwIP | awk '{ print $3 }')

if [[ "$_chkgwIP" = "$_gwIP" ]]; then
	printf "$green%s$transparent\n" "[Success]"
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
        exit 1
fi

## Check public Container IP ##
if [[ $_torip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	
	if [ "$_clearip" != "$_torip" ]; then
		printf "%s\n" "Workstation IP: $_torip"
		printf "$green%s$transparent\n" "[Success]"
	else	
		printf "$red%s$transparent\n" "[Error..]"
		exit 1
	fi
else
	printf "$red%s$transparent" "[Error getting an IP Adress:]"
        echo $_ip
	exit 1
fi

sleep 1
}
checkip
############### MENU ########################
revisit=0

function menu {
	clear
	if [ "$revisit" = "1" ]; then
		clear
	fi

	printf "\n\n$white%s$transparent\n\n" "What shall we do next?" 
	printf "%s\n" "Start a Terminal Session .......(t)"
	printf "%s\n" "Start a VNC Session ............(v)"
	printf "%s\n" "Check Connection ...............(c)" 
	printf "%s\n" "Quit and clean up ..............(q)" 


}

	while [ "$choice" != "q" ]
	do
		menu
		printf "\n\n%s" ""
		read choice
			if [ "$choice" = "t" ]; then
				clear
				printf "\n$white%s$transparent\n" "Connecting to Workstation Terminal.. (type 'exit' to return to menu)"
	        		sleep 1
				docker exec -it -e USER=root $_wsID /bin/bash
			        revisit=1
			fi
			if [ "$choice" = "v" ]; then
				clear
				printf "\n$white%s$transparent\n" "Starting VNC Server in Workstation... (close vncviewer to return to menu)"
	        		sleep 1
				docker exec -it -e USER=root $_wsID vncpasswd
				docker exec -it -e USER=root $_wsID su -c "vncserver :2" root
				vncviewer $_wsIP:2
				docker exec -it -e USER=root $_wsID su -c "vncserver -kill :2" root
			        revisit=1
			fi
			if [ "$choice" = "c" ]; then
				printf "\n\n%s" ""
				checkip
				printf "\n%s" "Press any key..."

			fi

	
	done



########## Start a VNC Server within our workstation container ##########

#printf "\n%b\n" "Starting a VNC Server..."
#docker exec -it -d $_wsID /bin/bash export USER=root
#docker exec -it $_wsID /bin/bash
#docker exec -it -d $_wsID vncserver :1
#docker exec -it -d $_wsID /root/.vnc/xstartup


########## Starting a VNC Session ###########

#printf "\n%b\n" "Starting a VNC Session..."
#vncviewer 192.168.0.3:5901


########## Cleaning up ##########

function quit {
printf "\n%b\n" "Clean up everything..."
#docker stop $_gwID
printf "\n%b" "Containers removed:" 
echo "$(docker stop $(docker ps -a -q))"
#docker rm $(docker ps -a -q)
printf "\n$white%b$transparent\n" "Bye bye.."
sleep 2

}
quit
exit 0
