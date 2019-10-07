# CloudHSM Sign operations

## OpenSSL environment setup
(https://docs.aws.amazon.com/cloudhsm/latest/userguide/openssl-library-install.html)

export n3fips_password=api_user:1234Qwer

java -cp .:/opt/cloudhsm/java/* MySign

/opt/cloudhsm/bin/key_mgmt_util
loginHSM -u CU -s api_user -p 1234Qwer

findKey -l signing_key -c 3

getCaviumPrivKey -k 786440 -out fake_priv.key

openssl req -engine cloudhsm -new -x509 -days 365 -subj '/CN=my key/' -sha256 -key fake_priv.key -out cert.pem

openssl x509 -in certificate.crt -text -noout

openssl dgst -engine cloudhsm -sha512 -sign fake_priv.key -out sign.txt.sha512 sign.txt

base64 sign.txt.sha256

openssl dgst -sha256 -verify < (openssl x509 -in cert.pem  -pubkey -noout) -signature sign.txt.sha256 sign.txt

vi cloudhsm.sign.txt.sha512.txt
base64 -d cloudhsm.sign.txt.sha512.txt > cloudhsm.sign.txt.sha512
openssl dgst -sha256 -verify <(openssl x509 -in cert.pem  -pubkey -noout) -signature cloudhsm.sign.txt.sha256 sign.txt

openssl req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -key private.pem -out cert1.pem

openssl pkcs12 -inkey private.pem -in cert1.pem -export -out private.pfx


## Converting and importing PKCS12 keys into CloudHSM
1. Convert PKCS12 file to PEM file

    openssl pkcs12 -in private.pfx -nocerts -out private-export.pem -passin pass:mypassword -passout pass:mypassword

2. Create key file with no password for importing into CloudHSM

    openssl rsa -in private-export.pem -out private-nopass.key -passin pass:mypassword

3. Log in to the CloudHSM

    /opt/cloudhsm/bin/key_mgmt_util

    loginHSM -u CU -s user -p password

4. Generate import keys on CloudHSM

    genSymKey -l import -t 31 -s 32 

5. Import keys to CloudHSM

    importPrivateKey -l sign-demo-key-imported -f private-nopass.key -w <import_key_handle>

6. Exit the CloudHSM key management agent

    exit

7. Delete the key file with no password

    rm private-nopass.key

