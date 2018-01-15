This folder contains useful files for setting up docker development
environment and allowing yextend to be built under docker.

The simplest way is to use Ubuntu Xenial and setup docker build
environment.

These are the steps - assuming you have shell in this folder:

* $ docker build --build-arg user=$USER --build-arg uid=`id -u $USER` --build-arg gid=`id -g $USER` -f dockerfile-amd64-ubuntu-xenial . -t yextend-ubuntu-xenial

This command builds docker environment using Ubuntu Xenial (16.04)
Alternatively - you can run the provided build-container.sh script:

* $ ./build-container.sh

This will build the container for your host's environment.

To run the docker container - issue the command:

* docker run -it --hostname yextend-build -v $HOME/src/yextend:/yextend yextend-ubuntu-xenial

If your host's OS is different than Ubuntu Xenial - adjust for your
host's environment.

Assuming the yextend project has been cloned to $HOME/src/yextend.
You are presented with a docker shell:

* bayshore@yextend-build:/$

The docker contained maps your $HOME/src/yextend folder to /yextend
In order to build yextend - issue the following commands:

	bayshore@yextend-build:/$ cd /yextend/
	bayshore@yextend-build:~$ ./autogen.sh
	bayshore@yextend-build:~$ ./configure && make

This will build yextend in your $HOME/src/yextend folder.
If you wish to run the built-in unit tests - issue:

* bayshore@yextend-build:~$ make unittests

Example output:
	cd test; nosetests -s; cd ..
	....................
	----------------------------------------------------------------------
	Ran 20 tests in 0.004s
	 
	OK


BayshoreNetworks provides docker build files for:

* Ubuntu Xenial - dockerfile-amd64-ubuntu-xenial
* Ubuntu Artful - dockerfile-amd64-ubuntu-artful
* Debian Stretch - dockerfile-amd64-debian-stretch
* Debian Stretch - dockerfile-amd64-debian-jessie
* Fedora Core 27 - dockerfile-amd64-fedora
* Raspberry Pi - dockerfile-armhf-raspbian-stretch
* HardKernel Odroid C1 - dockerfile-armhf-ubuntu-xenial

If you would like additional docker files - please contact BayshoreNetworks.
