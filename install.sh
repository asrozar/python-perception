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
hostname=$(hostname)
install_log="/tmp/python-perception-install.log"
es_pgp_key="deb https://artifacts.elastic.co/packages/5.x/apt stable main"
es_config="/etc/elasticsearch/elasticsearch.yml"
unsupported="Perception is built for Kali Linux, this system is unsupported"
dmi_product_id="/sys/devices/virtual/dmi/id/product_uuid"
product_uuid="/etc/product_uuid"
python_shebang="#!/usr/bin/python2"
generator_msg="# generated via install.sh"
importsys="import sys"
ifnamemain="if __name__ == \"__main__\":"
py_sysexit="    sys.exit(main())"
etc_perception="/etc/perception/"
perception_config="/usr/local/lib/python2.7/dist-packages/perception/config/"
postgresql_config="/etc/postgresql/9.6/main/postgresql.conf"
perceptiond="/usr/bin/perceptiond"
perception_cli="/usr/bin/perception_cli"
perceptiond_service="perceptiond.service"
end_msg="\n[*] Perception installation is complete\n[*] Complete the configuration at /etc/perception/config/configuration.py\n[*] To start the Perception Daemon on boot type \"systemctl enable perceptiond.service\""

if [[ ! "$kernal" =~ "kali4" ]];
then
    echo ${unsupported}
    exit 1
fi

read -r -p "[!] Is this installation of Perception for a contained install? [Y/N]: " contained_input

apt-get install -y python-setuptools python-alembic > ${install_log}
python setup.py sdist > ${install_log}

if [ $? -eq 0 ];

then
    chmod 666 ${install_log}
    perception_zip=$(ls -1 dist | tr '\n' '\0' | xargs -0 -n 1 basename)

    # make sure pip2 is installed
    which pip2 >> ${install_log}

    if [ $? -ne 0 ];
    then
        apt-get install python-pip -y >> ${install_log}
    fi

    # use pip2 to install or upgrade
    pip2 install --upgrade dist/${perception_zip} >> ${install_log}

    if [ $? -eq 0 ];
    then
        cat ${dmi_product_id} > ${product_uuid}

        if [ ! -L ${etc_perception} ];

            then
                mkdir ${etc_perception} >> ${install_log}
                ln -s ${perception_config} ${etc_perception} >> ${install_log}

        fi

        if [[ ! -f ${perceptiond} ]];

        then
            echo ${python_shebang} > ${perceptiond};
            echo ${generator_msg} >> ${perceptiond};
            echo >> ${perceptiond};
            echo ${importsys} >> ${perceptiond};
            echo >> ${perceptiond};
            echo "from perception.daemon import main" >> ${perceptiond};
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
            echo "from perception.shell import main" >> ${perception_cli};
            echo >> ${perception_cli};
            echo >> ${perception_cli};
            echo ${ifnamemain} >> ${perception_cli};
            echo "${py_sysexit}" >> ${perception_cli};
            echo >> ${perception_cli};
            chmod +x ${perception_cli}
        fi
    fi

    if [[ ! -f "/etc/systemd/system/perceptiond.service" ]];
    then
        cp ${perceptiond_service} "/etc/systemd/system/perceptiond.service" >> ${install_log}
        if [[ ! -f ${etc_perception}"configuration.py" ]];
        then
            cp ${perception_config}"configuration-example.py" ${etc_perception}"config/configuration.py" >> ${install_log}
            chmod 640 ${etc_perception}"config/configuration.py" >> ${install_log}
        fi
    fi

    case ${contained_input} in
        [nN][oO][nN])
        echo -e ${end_msg}
        exit 0
    esac

    DBPASSWD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - >> ${install_log}
    apt-get install apt-transport-https -y >> ${install_log}
    echo ${es_pgp_key} >> /etc/apt/sources.list.d/elastic-5.x.list
    apt-get update && apt-get install -y elasticsearch rabbitmq-server openjdk-8-jdk >> ${install_log}
    sed -i "s/#cluster.name: my-application/cluster.name: perception_cluster/" ${es_config} >> ${install_log}
    sed -i "s/#node.name: node-1/node.name: ${hostname}/" ${es_config} >> ${install_log}
    sed -i "s/port = 5435/port = 5432/" ${postgresql_config} >> ${install_log}
    systemctl enable postgresql.service elasticsearch.service rabbitmq-server.service >> ${install_log}
    systemctl start postgresql.service elasticsearch.service rabbitmq-server.service >> ${install_log}
    sed -i "s/perceptiondb_user_password/${DBPASSWD}/" ${etc_perception}"config/configuration.py" >> ${install_log}
    su postgres -c "createdb perceptiondb"
    python run_migrations.py ${DBPASSWD} >> ${install_log}
    echo -e ${end_msg}
    exit 0

elif [ $? -ne 0 ];
then
    echo "[!] The python-perception package did not install properly"
    echo "[*] Please review the install log: ${install_log}"
    exit 1
fi
