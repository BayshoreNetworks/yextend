#!/usr/bin/env bash

arch=`dpkg --print-architecture`
id=`lsb_release -si`
distr=`lsb_release -sc`
user=`whoami`
docker build --build-arg user=$user --build-arg uid=`id -u $user` --build-arg gid=`id -g $user` -f dockerfile-${arch}-${id,,}-${distr} . -t yextend-${id,,}-${distr}

exit 0
