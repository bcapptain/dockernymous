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
#VNC Target resolution
vncres="1366x768"
#Get the name of the default terminal emulator
term=$(ps -o comm= -p "$(($(ps -o ppid= -p "$(($(ps -o sid= -p "$$")))")))")

#####Output Colors#############
white="\033[1;37m"
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
blue="\033[1;34m"
transparent="\e[0m"

########################################
### ANONYMIZING MIDDLEBOX SETTINGS######
############ FOR TORRC #################

#These settings are pushed to the torrc of the gateway container.
_torSettings="VirtualAddrNetworkIPv4 10.192.0.0/10
Log notice file /root/.tor/notices.log
DataDirectory /root/.tor
Log notice stdout
SocksPort $_gwIP:9050 IsolateSOCKSAuth 
SocksPolicy accept 192.168.0.0/24
SocksPolicy reject *
ControlPort $_gwIP:9051
CookieAuthentication 1
HashedControlPassword 16:0430F4846DCB79EB605DAB188CF619860A18B86C20D075B84CB97E0695
AutomapHostsOnResolve 1
TransPort $_gwIP:9040 
DNSPort $_gwIP:53
#UseBridges 1 
#Bridge obfs4 185.163.45.31:8080 EC10BB3A20D7340E6CBDCFF7512E791FE5608CA2 cert=GscSlqpebDRkXrdHerr60Nbf3M1bzz5j3f2CDkp6KTvLDQPj577Zr+qGmrqLPgQcQqkhQA iat-mode=0
#Bridge obfs4 35.176.30.153:9443 47E180E5FF5AE051F151A1344536FAA279C258E7 cert=BdDwSVjkvOg8CuCqRehfh8AT0p9S6FluJKB+9/BSabJxF8B7hFNMbfE2UBNKOjSA3gQWPw iat-mode=0
#Bridge obfs4 45.79.220.128:9443 7645100FA563470B8DDB7AE43A44E5EADA3E0F7B cert=dKBeLjNQxjbDd3dT56nmrdkw5DmjMvI4tBBfp9uQ+6/cqmLskT0eXtKGh8mlxgdUMDVTPQ iat-mode=0"

#########################################
########## Functions ####################

function startupChecks {
	#Make sure we are root
	if [ "$(whoami)" != "root" ]; then
		printf "$red%s$transparent\n\n" "[This script needs to be run as root or with sudo.]"
		exit 1
	fi
	
	##	Is Docker Daemon running?
	docker ps &> /dev/null
	if [ $? -ne 0 ]; then
		printf "$red%s$transparent\n\n" "[Docker daemon not running or permission denied...]"
		exit 1
	fi
	#If we dont have an internet connection nothing makes sense at all...
	_clearip=$(curl --silent https://canihazip.com/s)
	## Check clear net IP ##
	if [[ $_clearip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			echo ""
	else
			printf "$red%s$transparent\n\n" "[Error. Do we have at least an internet connection?!]"
			exit 1
	fi
	
	#If there are any stopped containers, return 1 (true) or 0 (false)
	if [ "$(docker ps -a | grep "$_gwName\|$_wsName")" != "" ]; then
			
			return 1
	else 	return 0
	fi
	
	rm log &> /dev/null

	
	return 0
}

function remove_container {
		printf "\n$yellow%s$transparent\n" "[Deleting previously used containers..]"
		docker stop $(docker ps -a | grep "$_gwName\|$_wsName" | awk '{ print$1 }') &> /dev/null
		docker rm $(docker ps -a | grep "$_gwName\|$_wsName" | awk '{ print$1 }') &> /dev/null
}

function gw_start {
	########## Start a Containainer from the Gateway Image ##########
	printf "$white%s$transparent\n" "Starting a Gateway Container..."
	_gwID=$(docker run -it --rm --privileged -d $_gwName) 

	if [ "$_gwID" != "" ]; then
		printf "%s\n" "Container started with ID: $_gwID"
		printf "$green%s$transparent\n" "[Success!]"
		
	else
		printf "\n$red%s$transparent\n" "[Error getting Container ID. See above errors!]"
		return 1
	fi

	########### Connect Container to internal Network ################
	printf "\n$white%s$transparent\n" "Connecting internal Network..."
	docker network connect --ip $_gwIP $_intNW $_gwID
	if [ $? -ne 0  ]; then
		printf "\n$red%s$transparent\n" "[Error connecting to internal Docker Network.]"
		return 2
	fi
	printf "$green%s$transparent\n" "[Success!]"
	return 0
}

function start_tor {
	########## Start Tor in Container ##########
	printf "\n$white%s$transparent\n" "Starting Tor within gateway..."
	docker exec -it -d $_gwID sh -c "echo '$_torSettings' > /etc/tor/torrc"
	docker exec -it -d $_gwID sh -c "pkill tor"
	docker exec -it -d $_gwID sh -c "tor > log"
	sleep 2
	test=""
	declare -i timeout
	declare -i try
	timeout=0
	try=0

	while [ "$test" !=  "100%" ]
	do
		test=$(docker exec -it $_gwID /bin/sh -c "cat log" | tail -n1 | awk '{ print $6 }' | cut -d':' -f1)
		printf "\033[K%s\r" "Connection Status: $test"
		sleep 1
		timeout+=1
		if [ $timeout -eq 20 ]; then
			if [ "$try" = "3" ]; then
				printf "$yellow%s$transparent\n" "[Tried three times. Giving up..]"
				sleep 2
				return 1
			fi
			try+=1
			printf "$yellow%s$transparent\n" "[Connection timeout. Retry..]"
			docker exec -it -d $_gwID /bin/sh -c "pkill tor"
			docker exec -it -d $_gwID /bin/sh -c "rm -rf /root/.tor"
				sleep 2
			docker exec -it -d $_gwID sh -c "tor > log"
			sleep 2
			timeout=0
			
			
		fi
	done
	printf "$green%s$transparent\n" "[Success!]"
	sleep 1
	return 0
}

function stop_tor {
		printf "\n$white%s$transparent\n" "Stopping Tor in gateway..."
		docker exec -it -d $_gwID /bin/sh -c "pkill tor"
		docker exec -it -d $_gwID /bin/sh -c "rm -rf /root/.tor"
		docker exec -it -d $_gwID /bin/sh -c "rm -rf log"
		
		if [ "$(docker exec -it -d $_gwID /bin/sh -c "pgrep tor")" = "" ]; then
				printf "$green%s$transparent\n" "[Success!]"
		else	printf "$red%s$transparent\n" "[Stopping Tor was not successful!]"
		fi
		return 0
}

function ipt_rules {
	########## IPTABLES RULES ###########
	printf "\n$white%s$transparent\n" "Applying iptables rules..."
	#TransPort
	_trans_port="9040"
	#internal interface name
	_inc_if="eth1"
	# exlude from Tor
	_NON_TOR="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
	docker exec -it $_gwID sh -c "iptables -F"
	docker exec -it $_gwID sh -c "iptables -X"
	docker exec -it $_gwID sh -c "iptables -t nat -F"
	docker exec -it $_gwID sh -c "iptables -t nat -X"
	###
	#The following iptable rules are recommendations from the Tor Project https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy

	#docker exec -it $_gwID sh -c "iptables -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix 'Transproxy ctstate leak blocked: ' --log-uid"
	docker exec -it $_gwID sh -c "iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP"
	docker exec -it $_gwID sh -c "iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix 'Transproxy state leak blocked: ' --log-uid"
	docker exec -it $_gwID sh -c "iptables -A OUTPUT -m state --state INVALID -j DROP"

	docker exec -it $_gwID sh -c "iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,FIN ACK,FIN -j LOG --log-prefix 'Transproxy leak blocked: ' --log-uid"
	docker exec -it $_gwID sh -c "iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j LOG --log-prefix 'Transproxy leak blocked: ' --log-uid"
	docker exec -it $_gwID sh -c "iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,FIN ACK,FIN -j DROP"
	docker exec -it $_gwID sh -c "iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j DROP"

	for NET in $NON_TOR; do
		docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -d $NET -j RETURN"
	done

	docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -p udp --dport 53 -j REDIRECT --to-ports 53"
	docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -p udp --dport 5353 -j REDIRECT --to-ports 53"
	#docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if -p tcp --syn -j REDIRECT --to-ports $_trans_port"
	##exclude connections to the socket
	docker exec -it $_gwID sh -c "iptables -t nat -A PREROUTING -i $_inc_if ! -d 192.168.0.254 -p tcp --syn -j REDIRECT --to-ports $_trans_port"
	printf "$green%s$transparent\n" "[Success!]"
	return 0
}

function ws_start {
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

	########## Set the gateway as nameserver ##########
	printf "\n$white%s$transparent\n" "Setting the gateway as nameserver..."
	docker exec -it -d $_wsID sh -c "echo nameserver $_gwIP > /etc/resolv.conf"
	if [ "$?" = "0" ]; then
			printf "$green%s$transparent\n" "[Success!]"
	else 	printf "$red%s$transparent\n" "[Error!]"
	fi
	
	

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
		printf "$red%s$transparent\n" "[Error setting the default gateway]"
		echo $_chkgwIP
		exit 1
	fi
}

function checkip {
	##################################
	########## Checking IP ###########
	##################################
	printf "\n$white%s$transparent\n" "Checking connection..."
	#Check if tor is running in gw container
	if [ "$(docker exec -it $_gwID sh -c 'pgrep tor')" = "" ]; then
			printf "$yellow%s$transparent\n" "[Tor is not running in gateway]"
			return 0		
	fi
	
	_torip=$(docker exec -it $_wsID sh -c "curl --silent https://canihazip.com/s")
	_clearip=$(curl --silent https://canihazip.com/s)

	## Check clear net IP ##
	if [[ $_clearip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		printf "%s\n" "Host IP: $_clearip"        
	else
			printf "$red%s$transparent" "[Error. Do we have an Internet connection?]"
			
			return 0
	fi

	## Check public Container IP ##
	if [[ $_torip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		
		if [ "$_clearip" != "$_torip" ]; then
			printf "%s\n" "Workstation IP: $_torip"
			printf "$green%s$transparent\n" "[Success!]"
			sleep 2
			return 0
		fi
	else
		printf "$red%s$transparent" "[Error getting an IP Adress!]"
		printf "\n%b\n" "Retry? Tor may needs some time to establish circuits!"
		printf "%b" "Choice (y/n): "
		read retry
		if [[ $retry == "y" ]]; then
				return 1
		else 	return 0
		fi
		
		
		
	fi
	sleep 2
}

function start_vnc {
				printf "$white%s$transparent\n" "Starting VNC Server in Workstation... (close vncviewer to return to menu)"
	        	sleep 1
				_checkvnc=$(docker exec -it -e USER=root $_wsID bash -c "pgrep Xtightvnc")
				if [ "$_wsIP" = "" ]; then
					_wsIP=$(docker exec -it $_wsID sh -c "ip a | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'")
				fi
				if [ "$_checkvnc" = "" ]; then
					#docker exec -it -e USER=root $_wsID vncpasswd
					docker exec -it -e USER=root $_wsID su -c "rm -rf /tmp/.X2-lock" root
					docker exec -it -e USER=root $_wsID su -c "vncserver :2 -geometry $vncres" root
					if [ "$?" = "0" ]; then
							printf "$green%s$transparent\n" "[VNC-Server started]"
							sleep 2
					else	printf "$red%s$transparent\n" "[VNC-Server could not be started]"
							sleep 2
							return 1
					fi
						
					
				else 	printf "$green%s$transparent\n" "[Found running VNC-Server]"
						
				fi
				
				
				###Start the client###
				vncviewer $_wsIP:2 &> /dev/null &								
				#docker exec -it -e USER=root $_wsID su -c "vncserver -kill :2" root
				return 0
}

function menu {
	############### MENU ########################
	clear
	printf "$red%b\n" '       __           __                                                   '
	printf "$red%b\n" '  ____/ /___  _____/ /_____  _________  __  ______ ___  ____  __  _______'
	printf "$red%b\n" ' / __  / __ \/ ___/ //_/ _ \/ ___/ __ \/ / / / __ `__ \/ __ \/ / / / ___/'
	printf "$red%b\n" '/ /_/ / /_/ / /__/ ,< /  __/ /  / / / / /_/ / / / / / / /_/ / /_/ (__  ) '
	printf "$blue%b\n" '\__,_/\____/\___/_/|_|\___/_/  /_/ /_/\__, /_/ /_/ /_/\____/\__,_/____/  '
	printf "$blue%b\n" '                                     /____/                              '
	printf "$white%s$transparent\n" 					"-------------------------------------------------------------------------" 
	printf "$blue%s\t$white%s\t\t%s$transparent\n" 		"[Workstation]" "Start a Terminal Session"	"(t)"
	printf "$blue%s\t$white%s\t\t\t%s$transparent\n" 		"[Workstation]" "Start a VNC Session" 		"(v)"
	printf "$yellow%s\t$white%s\t\t%s$transparent\n" 		"[Gateway]" "Start a Terminal Session" 		"(g)"
	printf "$yellow%s\t$white%s\t\t\t\t%s$transparent\n" 	"[Gateway]" "(Re)Start Tor" 				"(s)"
	printf "$yellow%s\t$white%s\t\t\t\t%s$transparent\n" 	"[Gateway]" "Stop Tor" 						"(x)"
	printf "$yellow%s\t$white%s\t\t\t\t%s$transparent\n" 	"[Gateway]" "New Identity" 					"(n)"
	printf "%s\t$white%s\t\t\t%s$transparent\n" 			"[System]" "Check Connection" 				"(c)"
	printf "%s\t$white%s\t\t\t%s$transparent\n" 			"[System]" "Quit and clean up" 				"(q)" 
	
	
	# return values: 1=reload menu, 0=exit menu
	
	while [ "$choice" != "q" ]
	do
		printf "\n\n%s" ""
		printf "%s" "Choice (t/v/g/s/x/n/c/q): "
		read choice
			## Connect to work station terminal
			if [ "$choice" = "t" ]; then
				clear
				printf "$white%s$transparent\n" "Connecting to Workstation Terminal.. (type 'exit' to return to menu)"
	        		sleep 1
				$term -e "docker exec -it -e USER=root $_wsID /bin/bash" &> /dev/null &
			    return 1
			fi
			## Start and connect workstation VNC
			if [ "$choice" = "v" ]; then
				clear
				start_vnc
				return 1
			        
			fi
			## Check Connection
			if [ "$choice" = "c" ]; then
				printf "\n%s" ""
				checkip
				while [ "$?" = "1" ]
				do
					checkip
				done
				printf "\n%s" "Press any key..."
				read p
				return 1
			fi
			
			## New identity via ControlPort
			if [ "$choice" = "n" ]; then
				printf "\n$white%s$transparent\n" "Getting new identity..."
				docker exec -it $_gwID sh -c "(echo authenticate '""'; echo signal newnym; echo quit) | nc $_gwIP 9051"
				checkip
				printf "\n%s" "Press any key..."
				read p
				return 1
			fi
			
			
			## connect to gateway terminal
			if [ "$choice" = "g" ]; then
				clear
				printf "$white%s$transparent\n" "Connecting to Gateway Terminal.. (type 'exit' to return to menu)"
	        	sleep 1
				$term -e "docker exec -it -e USER=root $_gwID /bin/sh"  &> /dev/null &
			    return 1    
			fi
			
			# (re) start tor
			if [ "$choice" = "s" ]; then
				start_tor
				return 1
			fi
			
			# stop tor
			if [ "$choice" = "x" ]; then
				stop_tor
				return 1
			fi

	
	done
	
	if [ "$choice" = "q" ]; then
				printf "\n$white%s$transparent\n" "Do you want to keep the containers running?"
	        	printf "%s" "Choice (y/n): "
	        	read keep
					if [ "$keep" == "y" ]; then
							printf "\n$yellow%s$transparent\n" "Keeping containers running."
							printf "$yellow%s$transparent\n" "It's a good idea to stop Tor at least. Stop Tor?"
							printf "%s$transparent" "Choice (y/n): "
							read stoptor
							if [ "$stoptor" != "n" ]; then
									stop_tor
							fi 
							
					else 	remove_container
							return 0
					fi 
	return 0
	fi
	
	
}

function norestore_logic {
	gw_start
	while [ "$?" != "0" ]
	do
		gw_start
	done

	start_tor
	while [ "$?" != "0" ]
	do
		start_tor
	done

	ws_start
	while [[ "$?" != "0" ]]
	do
		ws_start
	done

	ipt_rules
	while [[ "$?" != "0" ]]
	do
		ipt_rules
	done

	checkip
	while [[ "$?" != "0" ]]
	do
		checkip
	done
	
	menu
	while [[ "$?" == "1" ]]
	do
		menu
	done
	return 0
	
}

function restore_logic {
	menu
	while [[ "$?" == "1" ]]
	do
		menu
	done
	return 0
	
}

### Program Logic aka sequence of function calls


##Banner
printf "$red%b\n" '       __           __                                                   '
printf "$red%b\n" '  ____/ /___  _____/ /_____  _________  __  ______ ___  ____  __  _______'
printf "$red%b\n" ' / __  / __ \/ ___/ //_/ _ \/ ___/ __ \/ / / / __ `__ \/ __ \/ / / / ___/'
printf "$red%b\n" '/ /_/ / /_/ / /__/ ,< /  __/ /  / / / / /_/ / / / / / / /_/ / /_/ (__  ) '
printf "$blue%b\n" '\__,_/\____/\___/_/|_|\___/_/  /_/ /_/\__, /_/ /_/ /_/\____/\__,_/____/  '
printf "$blue%b\n" '                                     /____/                              '



#Check wether there is a stored session of containers
startupChecks
if [ "$?" = "1" ]; then
		printf "\n$yellow%s$transparent\n" "Some containers were found. Try to restore session?"
		printf "%b" "Choice (y/n):  "
		read restore
					
		if [ "$restore" = "y" ]; then
				##Get the Gateway ID because the menu needs the variable _gwID
				if [ "$(docker ps -a | grep "my_gateway" | awk '{print $1}' | xargs)" != "" ]; then	
						
						_gwID=$(docker ps -a | grep $_gwName | awk '{print $1}' | xargs)
						printf "\n$green%s$transparent\n" "[Found gateway \"$_gwName\" with ID: $_gwID.]"
						sleep 1
				else 	printf "$yellow%s$transparent\n" "No Gateway with name $_gwName was found. Start one?"
						printf "$white%s$transparent" "Choice: "
						read startgw
						if [ "$startgw" = "y" ]; then
							gw_start
							start_tor
						fi
							
				fi
				##Get the Workstation ID because the menu needs the variable _wsID
				if [ "$(docker ps -a | grep "my_workstation" | awk '{print $1}' | xargs)" != "" ]; then	
						_wsID=$(docker ps -a | grep $_wsName | awk '{print $1}' | xargs)
						printf "\n$green%s$transparent\n" "[Found workstation \"$_wsName\" with ID: $_wsID.]"
						sleep 1
				else 	printf "$yellow%s$transparent\n" "No Workstation with name $_wsName was found. Start one?"
						printf "$white%s$transparent" "Choice (y/n):  "
						read startws
						if [ "$startws" = "y" ]; then
							ws_start
							
						fi
				fi
								
				restore_logic
				
		else	remove_container
				norestore_logic
		fi
					
else 	norestore_logic
fi

printf "\n$white%s$transparent\n" "[See you soon!]"
sleep 1
exit 0
