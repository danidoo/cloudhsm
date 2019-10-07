- Download java se 8
- install java se 8
set JAVA_HOME env variable
- download jce unlimited strength policy
unzip to $JAVA_HOME/jre/lib/security/
download & install cloudhsm jce library
sudo systemctl start cloudhsm-client

either:
    sudo cp /opt/cloudhsm/java/* $JAVA_HOME/jre/lib/ext/
    export LD_LIBRARY_PATH=/opt/cloudhsm/lib
or:
    java -Djava.library.path=.:/opt/cloudhsm/lib -cp .:/opt/cloudhsm/java/cloudhsm-1.0.jar ProgramName

sudo vi $JAVA_HOME/jre/lib/security/java.security
add -> security.provider.2=com.cavium.provider.CaviumProvider
git clone https://github.com/aws-samples/aws-cloudhsm-jce-examples.git


export HSM_USER="user"
export HSM_PASSWORD="password"
export HSM_PARTITION="PARTITION_1"



java -Djava.library.path=.:/opt/cloudhsm/lib -cp .:/opt/cloudhsm/java/* KeyUtilitiesRunner

vi HsmCredentials.properties
HSM_PARTITION = "PARTITION_1"
HSM_USER = "user"
HSM_PASSWORD = "password"
