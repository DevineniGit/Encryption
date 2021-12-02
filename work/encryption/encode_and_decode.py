#!/usr/bin/env python
# coding: utf-8

# Password Encryption



import base64
from base64 import *

pwd = 'thp_hal_password'
pwd_bytes = pwd.encode('ascii')
base64_bytes = base64.b64encode(pwd_bytes)
base64_pwd = base64_bytes.decode('ascii')

print(base64_pwd)


# Decoding
pwd_base64bytes = base64_pwd.encode('ascii')
pwd_bytes = base64.b64decode(pwd_base64bytes)
pwd_decode = pwd_bytes.decode('ascii')

print(pwd_decode)



#encoding method
pwd = 'passcode'

def encode_password(text_pwd):
    pwd_bytes = text_pwd.encode('ascii')
    base64_bytes = base64.b64encode(pwd_bytes)
    base64_pwd = base64_bytes.decode('ascii')
    return base64_pwd


print(encode_password(pwd))

#Decoding method

def decode_password(encoded_pwd):
    pwd_base64bytes = base64_pwd.encode('ascii')
    pwd_bytes = base64.b64decode(pwd_base64bytes)
    pwd_decode = pwd_bytes.decode('ascii')
    return pwd_decode


print(decode_password(encode_password))




import base64

encodedStr = "dGhwX2hhbF9wYXNzd29yZA=="

# # Standard Base64 Decoding
# decodedBytes = base64.b64decode(encodedStr)
# decodedStr = str(decodedBytes, "utf-8")


def decode_password(encodedStr):
    decodedBytes = base64.b64decode(encodedStr)
    decodedStr = str(decodedBytes, "utf-8")
    return decodedStr

print(decode_password(encodedStr))


def decrypt(f):
    f = open("/Users/udevi/documents/password.txt", "r")
    print(f.read())
    #token = base64.b64decode((read).encode('ascii')).decode('ascii')
    #return token

print(f.read())







