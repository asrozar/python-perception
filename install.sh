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
adduser_conf="/etc/adduser.conf"
etc_perception="/etc/perception"
perception_config="/usr/local/lib/python2.7/dist-packages/perception/config/"
perceptiond="/usr/bin/perceptiond"
perception_cli="/usr/bin/perception_cli"
perceptiond_service="perceptiond.service"
end_msg="\n[*] Perception installation is complete [*]\n[*] Complete the configuration at /etc/perception/configuration.py [*]\n[*] To start the Perception Daemon on boot type 'systemctl enable perceptiond.service' [*]"

if [[ ! "$kernal" =~ "kali" ]];
then
    echo "Perception is built for Kali Linux, this system is not Kali Linux"
    exit 1
fi

python setup.py sdist > /tmp/python-perception-sdist.log 2> /dev/null

if [ $? -eq 0 ];

then
    perception_zip=$(ls -1 dist | tr '\n' '\0' | xargs -0 -n 1 basename)

    which pip > /dev/null

    if [ $? -ne 0 ];
    then
        apt-get install python-pip -y > /tmp/python-pip-install.log 2> /dev/null;
    fi

    pip2 install dist/${perception_zip} > /tmp/python-perception-install.log 2> /dev/null;

    if [ $? -eq 0 ];
    then

        if [ ! -L ${etc_perception} ];

            then
                ln -s ${etc_perception} ${perception_config};

        fi

        if [[ ! -f ${perceptiond} ]];

        then
            echo "#!/usr/bin/python2" > ${perceptiond};
            echo "# generated via install.sh" >> ${perceptiond};
            echo "" >> ${perceptiond};
            echo "import sys" >> ${perceptiond};
            echo "" >> ${perceptiond};
            echo "from perception.perceptiond import main" >> ${perceptiond};
            echo "" >> ${perceptiond};
            echo "" >> ${perceptiond};
            echo "if __name__ == \"__main__\":" >> ${perceptiond};
            echo "    sys.exit(main())" >> ${perceptiond};
            echo "" >> ${perceptiond};
            chmod +x ${perceptiond}
        fi

        if [[ ! -f ${perception_cli} ]];

        then
            echo "#!/usr/bin/python2" > ${perception_cli};
            echo "# generated via install.sh" >> ${perception_cli};
            echo "" >> ${perception_cli};
            echo "import sys" >> ${perception_cli};
            echo "" >> ${perceptiond};
            echo "from perception.perception_cli import main" >> ${perception_cli};
            echo "" >> ${perception_cli};
            echo "" >> ${perception_cli};
            echo "if __name__ == \"__main__\":" >> ${perception_cli};
            echo "    sys.exit(main())" >> ${perception_cli};
            echo "" >> ${perception_cli};
            chmod +x ${perception_cli}
        fi
    fi
fi

if [[ ! -f "/etc/systemd/system/perceptiond.service" ]];
        then
            cp ${perceptiond_service} "/etc/systemd/system/perceptiond.service"
            if [[ ! -f ${etc_perception}"configuration.py" ]]
                then
                    cp ${perception_config}"configuration-example.py" ${etc_perception}"configuration.py"
                    chmod 640 ${perception_config}"configuration.py"
            fi
fi

read -r -p "Would you like to use Perception CLI as the default shell when adduser is invoked? [Y/N]: " input

case ${input} in
    [nN][oO][nN])
        echo -e ${end_msg}
        exit 1;
esac

sed -i "s/DSHELL=\/bin\/bash/DSHELL=\/usr\/bin\/perception_cli/" ${adduser_conf}
echo -e ${end_msg}
