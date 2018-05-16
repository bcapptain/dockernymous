**Warning:** 
Dockernymous is in a very early state of development. Only use it for educational purposes. 
**DON'T use it if you rely on strong anonymity**!


## **About:**

Dockernymous is a start script for Docker that runs and configures two individual Linux containers in order act as a anonymisation workstation-gateway set up.

It's aimed towards experienced Linux/Docker users, security professionals and penetration testers!

The gateway container acts as a Anonymizing Middlebox (see
[https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy)) and routes ALL traffic from the workstation container through the Tor Network.

The idea was to create a whonix-like setup (see [https://www.whonix.org](https://www.whonix.org)) that runs on
systems which aren't able to efficiently run two hardware  virtualized machines or don't have virtualization capacities at all.


## **Requirements:**

**Host (Linux):**
- docker
- vncviewer
- xterm
- curl

**Gateway Image:**
- Linux (e.g. Debian)
- tor
- xtightvnc
- procps
- ncat
- iptables

**Workstation Image:**
 - Linux (e.g. Kali)
 - ‎xfce4


## Instructions:

**1. Host**

    $ git clone https://github.com/bcapptain/dockernymous.git

Dockernymous needs an up and running Docker environment and a non-default docker network. Create one by:

    $ docker network create --driver=bridge --subnet=192.168.0.0/24 docker_internal

**2. Gateway (Debian):**

Get a (lightweight) gateway Image. For example Debian:

    $ docker pull debian

Run the image, update the distro, install iptables & tor:

    $ docker run -it debian /bin/bash

    $ apt-get update
    $ apt-get dist-upgrade
        
    $ apt-get install tor iptables procps netcat
    $ apt-get clean
    $ exit

Feel free to further customize your gateway for your needs.

To make this permanent you have to create an image from that customized container. Each time you run dockernymous a new container is created and disposed on exit:

    $ docker commit [Container ID] my_gateway

Get the container ID by running:

    $ docker ps -a


**3. Workstation (Kali Linux):**

Get an image for the Workstation. For example, Kali Linux for penetration testing:

    $ docker pull kalilinux/kali-linux-docker

Update and install the tools you would like to use (see
[https://www.kali.org/news/kali-linux-metapackages/](https://www.kali.org/news/kali-linux-metapackages/))

    $ docker run -it kalilinux/kali-linux-docker /bin/bash
    $ apt-get update
    $ apt-get dist-upgrade
    
    $ apt install kali-linux-top10

Make sure the tightvncserver and curl packages are installed which is the case with most Kali Metapackages.

    $ apt-get install tightvncserver
    $ apt-get install curl

Install xfce4 for a graphical Desktop:

    $ apt-get install xfce4 
    $ apt-get clean
    $ exit

As with the Gateway, to make this permanent you have to create an image from that customized container. Each time you run dockernymous a new container is created and disposed on exit.

    $ docker commit [Container ID] my_workstation

Get the container ID by running:

    $ docker ps -a

**4. Run dockernymous**
Open dockernymous.sh with your favorite editor and update the actual names of your images.

Everything should be set up by now. Run Dockernymus (from the host) as root or with sudo:

Everything should be set up now.
Run Dockernymus (from the host) as root or with sudo:

    $ sudo bash dockernymous.sh

 or mark it executable once:
 ‎

    $ chmod +x dockernymous.sh 

and always run it with:

    $ ./dockernymous.sh


