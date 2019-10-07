# CloudHSM Sign operations

## OpenSSL environment setup

https://docs.aws.amazon.com/cloudhsm/latest/userguide/openssl-library-install.html
<pre>
export n3fips_password=user:password

java -cp .:/opt/cloudhsm/java/* MySign

/opt/cloudhsm/bin/key_mgmt_util
loginHSM -u CU -s user -p password

findKey -l signing_key -c 3

getCaviumPrivKey -k 786440 -out fake_priv.key

openssl req -engine cloudhsm -new -x509 -days 365 -subj '/CN=my key/' -sha256 -key fake_priv.key -out cert.pem

openssl x509 -in certificate.crt -text -noout

openssl dgst -engine cloudhsm -sha256 -sign fake_priv.key -out sign.txt.sha256 sign.txt

base64 sign.txt.sha256

openssl dgst -sha256 -verify < (openssl x509 -in cert.pem  -pubkey -noout) -signature sign.txt.sha256 sign.txt

vi cloudhsm.sign.txt.sha256.txt
base64 -d cloudhsm.sign.txt.sha256.txt > cloudhsm.sign.txt.sha256
openssl dgst -sha256 -verify <(openssl x509 -in cert.pem  -pubkey -noout) -signature cloudhsm.sign.txt.sha256 sign.txt

openssl req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -key private.pem -out cert1.pem

</pre>

## Converting and importing PKCS12 keys into CloudHSM
1. Convert PKCS12 file to PEM file

<pre>openssl pkcs12 -in private.pfx -nocerts -out private-export.pem -passin pass:mypassword -passout pass:mypassword</pre>

2. Create key file with no password for importing into CloudHSM

<pre>openssl rsa -in private-export.pem -out private-nopass.key -passin pass:mypassword</pre>

3. Log in to the CloudHSM

<pre>/opt/cloudhsm/bin/key_mgmt_util
loginHSM -u CU -s user -p password</pre>

4. Generate import keys on CloudHSM

<pre>genSymKey -l import -t 31 -s 32</pre> 

5. Import keys to CloudHSM

<pre>importPrivateKey -l sign-demo-key-imported -f private-nopass.key -w &lt;import_key_handle&gt;</pre>

6. Exit the CloudHSM key management agent

<pre>exit</pre>

7. Delete the key file with no password

<pre>rm private-nopass.key</pre>

