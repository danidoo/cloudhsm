# https://github.com/bentonstark/py-hsm

from pyhsm.hsmclient import HsmClient

c = HsmClient(pkcs11_lib="/opt/cloudhsm/lib/libcloudhsm_pkcs11.so")

c.open_session(slot=1)

for s in c.get_slot_info():
    print("----------------------------------------")
    print(s.to_string())

c.login(pin="api_user:!234Qwer")

from pyhsm.hsmenums import HsmSymKeyGen
key_handle = c.create_secret_key(key_label="my_aes_key",
                                   key_type=HsmSymKeyGen.AES,
                                   key_size_in_bits=256,
                                   token=True,
                                   private=True,
                                   modifiable=False,
                                   extractable=False,
                                   sign=True,
                                   verify=True,
                                   decrypt=True,
                                   wrap=True,
                                   unwrap=True,
                                   derive=False)

key_handle = c.create_secret_key(key_label="my_aes_key",
                                   key_type=HsmSymKeyGen.AES,
                                   key_size_in_bits=256)

#from pyhsm.hsmenums import HsmUser
#c.open_session(slot=1,user_type=HsmUser.SecurityOfficer)


key_handles = c.create_rsa_key_pair(public_key_label="my_rsa_pub",
                                      private_key_label="my_rsa_pvt",
                                      key_length=2048,
                                      public_exponent=b"\x01\x00\x01",
                                      token=True,
                                      modifiable=False,
                                      extractable=False,
                                      sign_verify=True,
                                      encrypt_decrypt=True,
                                      wrap_unwrap=True,
                                      derive=False)

# https://github.com/danni/python-pkcs11/
import pkcs11
lib = pkcs11.lib("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so")
token = lib.get_token()
session = token.open(user_pin='api_user:!234Qwer')




    1  python3
    2  pip install python-pkcs11
    3  pip install python-pkcs11 --user
    4  sudo yum install python3-dev 
    5  sudo yum install pkcs11
    6  sudo yum install -y cmake gcc gcc-c++ openssl-devel -y
    7  pip install python-pkcs11 --user
    8  sudo yum install openssl-pcks11
    9  sudo yum install p11-kit
   10  sudo yum install p11-dev
   11  sudo yum install python37-devel
   12  sudo yum install python37-dev
   13  python --version
   14  python3 --version
   15  sudo yum install python3.7-dev
   16  sudo yum install python3.7-devel
   17  sudo yum install python3-devel
   18  pip install python-pkcs11 --user
   19  python
   20  python3
   21  history