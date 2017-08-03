#!/bin/bash
###
## Perception
## Copyright (C) 2017  CriticalSecurity, LLC LLC (https://www.critical-sec.com/)
## See the file 'LICENSE.txt' for the license information
###

# Check if is it root
if [ $EUID -ne 0 ]; then
 echo "You must be root."
 exit 1
fi

# os check
arch=$(uname -m)
kernal=$(uname -r)

if [[ "$kernal" =~ *."kali".* ]];
then
    echo "it's kali";
else
    echo "Perception is built for Kali Linux, this system is not Kali Linux"
    exit 1
fi

python setup.py sdist

#if $? = 0;
