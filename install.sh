#!/bin/bash
###
## Perception Installer
## Copyright (C) 2017  CriticalSecurity, LLC LLC (https://www.critical-sec.com/)
## See the file 'LICENSE.txt' for the license information
###

# Check if is it root
if [ $EUID -ne 0 ]; then
 echo "You must be root."
 exit 1
fi

kernal=$(uname -r)
unsupported="Perception is built for Kali Linux, this system is unsupported"
dmi_product_id="/sys/devices/virtual/dmi/id/product_uuid"
product_uuid="/etc/product_uuid"
python_shebang="#!/usr/bin/python2"
generator_msg="# generated via install.sh"
importsys="import sys"
ifnamemain="if __name__ == \"__main__\":"
py_sysexit="    sys.exit(main())"
adduser_conf="/etc/adduser.conf"
etc_perception="/etc/perception/"
perception_config="/usr/local/lib/python2.7/dist-packages/perception/config/"
perceptiond="/usr/bin/perceptiond"
perception_cli="/usr/bin/perception_cli"
perceptiond_service="perceptiond.service"
end_msg="\n[*] Perception installation is complete\n[*] Complete the configuration at /etc/perception/config/configuration.py\n[*] To start the Perception Daemon on boot type \"systemctl enable perceptiond.service\""

# os check
if [[ ! "$kernal" =~ "kali4" ]];
then
    echo ${unsupported}
    exit 1
fi

# build the sdist package
python setup.py sdist > /tmp/python-perception-sdist.log 2> /dev/null

if [ $? -eq 0 ];

then
    perception_zip=$(ls -1 dist | tr '\n' '\0' | xargs -0 -n 1 basename)

    # make sure pip2 is installed
    which pip2 > /dev/null

    if [ $? -ne 0 ];
    then
        apt-get install python-pip -y > /tmp/python-pip-install.log 2> /dev/null;
    fi

    # use pip2 to install or upgrade
    pip2 install --upgrade dist/${perception_zip} > /tmp/python-perception-install.log 2> /dev/null;

    if [ $? -eq 0 ];
    then
        cat ${dmi_product_id} > ${product_uuid}

        if [ ! -L ${etc_perception} ];

            then
                mkdir ${etc_perception}
                ln -s ${perception_config} ${etc_perception} ;

        fi

        if [[ ! -f ${perceptiond} ]];

        then
            echo ${python_shebang} > ${perceptiond};
            echo ${generator_msg} >> ${perceptiond};
            echo >> ${perceptiond};
            echo ${importsys} >> ${perceptiond};
            echo >> ${perceptiond};
            echo "from perception.perceptiond import main" >> ${perceptiond};
            echo >> ${perceptiond};
            echo >> ${perceptiond};
            echo ${ifnamemain} >> ${perceptiond};
            echo "${py_sysexit}" >> ${perceptiond};
            echo >> ${perceptiond};
            chmod +x ${perceptiond}
        fi

        if [[ ! -f ${perception_cli} ]];

        then
            echo ${python_shebang} > ${perception_cli};
            echo ${generator_msg} >> ${perception_cli};
            echo >> ${perception_cli};
            echo ${importsys} >> ${perception_cli};
            echo >> ${perceptiond};
            echo "from perception.perception_cli import main" >> ${perception_cli};
            echo >> ${perception_cli};
            echo >> ${perception_cli};
            echo ${ifnamemain} >> ${perception_cli};
            echo "${py_sysexit}" >> ${perception_cli};
            echo >> ${perception_cli};
            chmod +x ${perception_cli}
        fi
    fi
fi

if [[ ! -f "/etc/systemd/system/perceptiond.service" ]];
        then
            cp ${perceptiond_service} "/etc/systemd/system/perceptiond.service"
            if [[ ! -f ${etc_perception}"configuration.py" ]]
                then
                    cp ${perception_config}"configuration-example.py" ${etc_perception}"config/configuration.py"

                    # TODO: how can I avoid this? Would rather this be 640
                    # CLI needs the config, may need to move sensitive info somewhere else
                    # or make cli use sudo???
                    chmod 644 ${etc_perception}"config/configuration.py"
            fi
fi

read -r -p "Is this installation of Perception for a contained install? [Y/N]: " contained_input

case ${contained_input} in
    [nN][oO][nN])
        echo
        # wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add
        # apt-get install apt-transport-https
        # echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
        # apt-get update && apt-get install -y elasticsearch rabbitmq-server openjdk-8-jdk
esac

read -r -p "Would you like to use Perception CLI as the default shell when adduser is invoked? [Y/N]: " cli_input

case ${cli_input} in
    [nN][oO][nN])
        echo -e ${end_msg}
        exit 1;
esac

sed -i "s/DSHELL=\/bin\/bash/DSHELL=\/usr\/bin\/perception_cli/" ${adduser_conf}
echo -e ${end_msg}
