
# for GUI


#pip instal tkinter
#pip install unidecode
#pip install pillow


import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk  # pip install pillow

from tkinter import filedialog as fd

# for normalizing text
import unidecode


# for encryption
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto import Random
from secrets import token_bytes # for random key generation
import base64
import random


#for comparision and graphs
import json
import time
import datetime
import matplotlib.pyplot as plt
import numpy as np


import timeit



#comparision plot
def plot_comparision(encclist,declist):
    top=tk.Toplevel()
    top.title("Comparision Graph ")
    
    fig, ax = plt.subplots()
    bar_width = 0.35
    X = np.arange(3)    

    p1 = plt.bar(X, encclist, bar_width, color='b',label='encryption')    
    
    p2 = plt.bar(X + bar_width, declist, bar_width,color='g',label='Decryption')

    plt.xlabel('Method')
    plt.ylabel('Time in ms')
    plt.title('Comparission AES vs DES vs RSA')
    plt.xticks(X + (bar_width/2) , ('DES','AES','RSA'))
    plt.legend()

    plt.tight_layout()
    plt.show()    
    
    
    
    btn2=tk.Button(top,text="Close",command=top.destroy).pack()





def open_aes_message(top):
    f = fd.askopenfilename()
    #print(f)
    
    global aes_messagefile
    aes_messagefile=f
    mylabel2=tk.Label(top,text="SELECTED FILE " +f ,font=("Arial",8),fg="black",bg="orange",height="3",width="70") #
    mylabel2.place(x=500, y=150)    


def open_aes_key( top ):
    f = fd.askopenfilename()
    #print(f)
    global aes_keyfile
    aes_keyfile=f
    mylabel3=tk.Label(top,text="SELECTED ENCRYPTION KEY " +f,font=("Arial",8),fg="black",bg="orange",height="3",width="70") #
    mylabel3.place(x=500, y=300)       


    


# aes encryption input page
def aes_encryp():
    top=tk.Toplevel()
    top.title("AES ENCRYPTION ")
    top.geometry('1000x800')
    top.configure(background='black')

        
    mylabel=tk.Label(top,text="AES ENCRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
    mylabel.place(x=60, y=10)
    
    mylabel2=tk.Label(top,text="ENTER MESSAGE FOR ENCRYPTION",font=("Arial",8),fg="black",bg="orange",height="3",width="30") #
    mylabel2.place(x=120, y=250)        

    entry = tk.Entry(top,font=("Arial",8),width="30")
    entry.insert(0,"") 


    entry.place(x=320, y=250 ,width=300,height=50)        


    mybutton3=tk.Button(top,text="ENCRYPT",font=("Arial",8),fg="white",bg="green",height="3",width="30",command=lambda: gaes_encryption(entry.get(),top,mybutton3))
    mybutton3.place(x=300, y=400)
    
    

    mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
    mybutton4.place(x=300, y=610)     




#aes calculation page
def gaes_encryption(msg,top="",mybutton3="",BLOCK_SIZE=32,pad="-"):
    #print(msg)
    msg=unidecode.unidecode(msg)
    aeskey=token_bytes(16)
    padding=lambda s : s+((BLOCK_SIZE - len(s)%BLOCK_SIZE))*pad 
    cipher=AES.new(aeskey,AES.MODE_ECB)
    result=cipher.encrypt(padding(msg).encode('utf-8'))
        
    if top=="":
        f = open('C:/Users/Asus/Downloads/encryption/aesencryption', 'wb') 
        f.write(result)
        f.close()        

        f = open('C:/Users/Asus/Downloads/encryption/aeskey', 'wb') 
        f.write(aeskey)
        f.close()    
    if top!="":
        timen=datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
    
        f = open('C:/Users/Asus/Downloads/encryption/aesencryption'+timen, 'wb') 
        f.write(result)
        f.close()    
        mybutton3.destroy()
        
        mylabel=tk.Label(top,text="AES ENCRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
        mylabel.place(x=60, y=10)
        
        mylabel2=tk.Label(top,text="ENCRYPTED MESSAGE",font=("Arial",8),fg="black",bg="green",height="3",width="30") #
        mylabel2.place(x=120, y=250)        
        


        entry = tk.Entry(top,font=("Arial",8),width="30")
        entry.insert(0,(str(result))) 
        entry.place(x=320, y=250 ,width=300,height=50)        



        mylabel2=tk.Label(top,text="ENCRYPTION KEY",font=("Arial",8),fg="black",bg="darkorange",height="3",width="30") #
        mylabel2.place(x=120, y=350)        
        


        ekey = tk.Entry(top,font=("Arial",8),width="30")
        ekey.insert(0,(str(aeskey))) 
        ekey.place(x=320, y=350 ,width=300,height=50)     

   

        f = open('C:/Users/Asus/Downloads/encryption/aeskey'+timen, 'wb') 
        f.write(aeskey)
        f.close()    

    return str(result)



# aes decryption input page
def aes_decryp(mode=0,BLOCK_SIZE=32,pad="-",top2=""):
    if top2!="":
        top2.destroy()
    if mode==0:
        top=tk.Toplevel()
        top.title("AES DECRYPTION ")
        top.geometry('1000x800')
        top.configure(background='black')   

        mylabel=tk.Label(top,text="AES DECRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
        mylabel.place(x=60, y=10)
        global aes_messagefile
        global aes_keyfile     
        f = open(aes_messagefile, 'rb') 
        message=f.read()
        f.close()
        f = open(aes_keyfile, 'rb') 
        key=f.read()
        f.close()
    
    elif mode==1:
        f = open('C:/Users/Asus/Downloads/encryption/aesencryption', 'rb') 
        message=f.read()
        
        f.close()    

        f = open('C:/Users/Asus/Downloads/encryption/aeskey', 'rb') 
        key=f.read()
        
        f.close()    
    
    decipher=AES.new(key,AES.MODE_ECB)
    pt=decipher.decrypt(message).decode('utf-8')
    pad_index=pt.find(pad)
    result=pt[:pad_index]
    #print(result)
    
    if mode==0:
        
        mylabel2=tk.Label(top,text="DECRYPTED MESSAGE",font=("Arial",8),fg="black",bg="green",height="3",width="30") #
        mylabel2.place(x=120, y=250)        
        


        entry = tk.Entry(top,font=("Arial",8),width="30")
        entry.insert(0,str(result)) 
        entry.place(x=320, y=250 ,width=300,height=50)  

        mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
        mybutton4.place(x=300, y=500)     




# des encryption input page
def des_encryp():
    top=tk.Toplevel()
    top.title("DES ENCRYPTION ")
    top.geometry('1000x800')
    top.configure(background='black')

        
    mylabel=tk.Label(top,text="DES ENCRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
    mylabel.place(x=60, y=10)
    
    mylabel2=tk.Label(top,text="ENTER MESSAGE FOR ENCRYPTION",font=("Arial",8),fg="black",bg="orange",height="3",width="30") #
    mylabel2.place(x=120, y=250)        

    entry = tk.Entry(top,font=("Arial",8),width="30")
    entry.insert(0,"") 


    entry.place(x=320, y=250 ,width=300,height=50)        


    mybutton3=tk.Button(top,text="ENCRYPT",font=("Arial",8),fg="white",bg="green",height="3",width="30",command=lambda: gdes_encryption(entry.get(),top,mybutton3))
    mybutton3.place(x=300, y=400)
    
    

    mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
    mybutton4.place(x=300, y=610)     



#des calculation
def gdes_encryption(msg,top="",mybutton3="",BLOCK_SIZE=8,pad="-"):
    #print(msg)
    msg=unidecode.unidecode(msg)
    
    
    deskey=token_bytes(8)
    padding=lambda s : s+((BLOCK_SIZE - len(s)%BLOCK_SIZE) )*pad 
    
    
    cipher=DES.new(deskey,DES.MODE_ECB)
    
    
    
    result=cipher.encrypt(padding(msg).encode('utf-8'))
    
    
    
    if top!="":
        timen=datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
    
        mybutton3.destroy()
        
        mylabel=tk.Label(top,text="DES ENCRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
        mylabel.place(x=60, y=10)
        
        mylabel2=tk.Label(top,text="ENCRYPTED MESSAGE",font=("Arial",8),fg="black",bg="green",height="3",width="30") #
        mylabel2.place(x=120, y=250)        
        


        entry = tk.Entry(top,font=("Arial",8),width="30")
        entry.insert(0,(str(result))) 
        entry.place(x=320, y=250 ,width=300,height=50)        



        mylabel2=tk.Label(top,text="ENCRYPTION KEY",font=("Arial",8),fg="black",bg="darkorange",height="3",width="30") #
        mylabel2.place(x=120, y=350)        
        


        ekey = tk.Entry(top,font=("Arial",8),width="30")
        ekey.insert(0,(str(result))) 
        ekey.place(x=320, y=350 ,width=300,height=50)     

        f = open('C:/Users/Asus/Downloads/encryption/desencryption'+timen, 'wb') 
        f.write(result)
        f.close()    

        f = open('C:/Users/Asus/Downloads/encryption/deskey'+timen, 'wb') 
        f.write(deskey)
        f.close()    




    else :
        f = open('C:/Users/Asus/Downloads/encryption/desencryption', 'wb') 
        f.write(result)
        f.close()    

        f = open('C:/Users/Asus/Downloads/encryption/deskey', 'wb') 
        f.write(deskey)
        f.close()    
    return str(result)

#des decryption
def des_decryp(mode=0,BLOCK_SIZE=8,pad="-",top2=""):
    if top2!="":
        top2.destroy()
    if mode==0:
        top=tk.Toplevel()
        top.title("DES DECRYPTION ")
        top.geometry('1000x800')
        top.configure(background='black')   

        mylabel=tk.Label(top,text="DES DECRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
        mylabel.place(x=60, y=10)
    
        global aes_messagefile
        global aes_keyfile     
        f = open(aes_messagefile, 'rb') 
        message=f.read()
        f.close()
        f = open(aes_keyfile, 'rb') 
        key=f.read()
        f.close()
        
    else:
        f = open('C:/Users/Asus/Downloads/encryption/desencryption', 'rb') 
        message=f.read()
        
        f.close()    

        f = open('C:/Users/Asus/Downloads/encryption/deskey', 'rb') 
        key=f.read()
        
        f.close()    
    
    decipher=DES.new(key,DES.MODE_ECB)
    pt=decipher.decrypt(message).decode('utf-8')
    pad_index=pt.find(pad)
    result=pt[:pad_index]
    
    if mode==0:
        #print(result)
        
        
        mylabel2=tk.Label(top,text="DECRYPTED MESSAGE",font=("Arial",8),fg="black",bg="green",height="3",width="30") #
        mylabel2.place(x=120, y=250)        
        


        entry = tk.Entry(top,font=("Arial",8),width="30")
        entry.insert(0,str(result)) 
        entry.place(x=320, y=250 ,width=300,height=50)  
        mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
        mybutton4.place(x=300, y=400)     





def rsa_encryp():
    top=tk.Toplevel()
    top.title("RSA ENCRYPTION ")
    top.geometry('1000x800')
    top.configure(background='black')

        
    mylabel=tk.Label(top,text="RSA ENCRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
    mylabel.place(x=60, y=10)
    
    mylabel2=tk.Label(top,text="ENTER MESSAGE FOR ENCRYPTION",font=("Arial",8),fg="black",bg="orange",height="3",width="30") #
    mylabel2.place(x=120, y=250)        

    entry = tk.Entry(top,font=("Arial",8),width="30")
    entry.insert(0,"") 


    entry.place(x=320, y=250 ,width=300,height=50)        


    mybutton3=tk.Button(top,text="ENCRYPT",font=("Arial",8),fg="white",bg="green",height="3",width="30",command=lambda: grsa_encryption(entry.get(),top,mybutton3))
    mybutton3.place(x=300, y=400)
    
    

    mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
    mybutton4.place(x=300, y=610)     





#rsa calculation functions
def rabinMiller(n, d):
    a = random.randint(2, (n - 2) - 2)
    x = pow(a, int(d), n) # a^d%n
    if x == 1 or x == n - 1:
        return True

    # square x
    while d != n - 1:
        x = pow(x, 2, n)
        d *= 2

        if x == 1:
            return False
        elif x == n - 1:
            return True
    
    # is not prime
    return False

def isPrime(n):
    """
        return True if n prime
        fall back to rabinMiller if uncertain
    """

    # 0, 1, -ve numbers not prime
    if n < 2:
        return False

    # low prime numbers to save time
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    # if in lowPrimes
    if n in lowPrimes:
        return True

    # if low primes divide into n
    for prime in lowPrimes:
        if n % prime == 0:
            return False
    
    # find number c such that c * 2 ^ r = n - 1
    c = n - 1 # c even bc n not divisible by 2
    while c % 2 == 0:
        c /= 2 # make c odd

    # prove not prime 128 times
    for i in range(128):
        if not rabinMiller(n, c):
            return False

    return True
    

def generateKeys(keysize=1024):
    e = d = N = 0

    # get prime nums, p & q
    p = generateLargePrime(keysize)
    q = generateLargePrime(keysize)

    #print(f"p: {p}")
    #print(f"q: {q}")

    N = p * q # RSA Modulus
    phiN = (p - 1) * (q - 1) # totient

    # choose e
    # e is coprime with phiN & 1 < e <= phiN
    while True:
        e = random.randrange(2 ** (keysize - 1), 2 ** keysize - 1)
        if (isCoPrime(e, phiN)):
            break

    # choose d
    # d is mod inv of e with respect to phiN, e * d (mod phiN) = 1
    d = modularInv(e, phiN)

    return e, d, N
    
    

def generateLargePrime(keysize):
    """
        return random large prime number of keysize bits in size
    """

    while True:
        num = random.randrange(2 ** (keysize - 1), 2 ** keysize - 1)
        if (isPrime(num)):
            return num

def isCoPrime(p, q):
    """
        return True if gcd(p, q) is 1
        relatively prime
    """

    return gcd(p, q) == 1

def gcd(p, q):
    """
        euclidean algorithm to find gcd of p and q
    """

    while q:
        p, q = q, p % q
    return p

def egcd(a, b):
    s = 0; old_s = 1
    t = 1; old_t = 0
    r = b; old_r = a

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # return gcd, x, y
    return old_r, old_s, old_t
    
    
def modularInv(a, b):
    gcd, x, y = egcd(a, b)

    if x < 0:
        x += b

    return x

def encrypt(e, N, msg):
    cipher = ""

    for c in msg:
        m = ord(c) # getting ascci value 
        cipher += str(pow(m, e, N)) + " "

    return cipher

def decrypt(d, N, cipher):
    msg = ""

    parts = cipher.split()
    for part in parts:
        if part:
            c = int(part)
            msg += chr(pow(c, d, N))

    return msg
    
 
def decryptor_base(endpoint):

    if endpoint==1:
        enctype="DES "
    elif endpoint==2:
        enctype="AES "
    else :
        enctype="RSA "

    top=tk.Toplevel()
    top.title(enctype+"DECRYPTION ")
    top.geometry('1000x800')
    top.configure(background='black')   

    mylabel=tk.Label(top,text=enctype+" DECRYPTION ",font=("Arial",14),fg="white",bg="brown",height="3",width="90") #
    mylabel.place(x=60, y=10)
    
    
        
    #aes_messagefile= " NA "
    #aes_keyfile=" NA "
    entry = tk.Button(top,font=("Arial",8),text="CLICK HERE TO SELECT ENCRYPTED MESSAGE FILE",width="30",command=lambda : open_aes_message(top))


    entry.place(x=120, y=150 ,width=300,height=50)        


    #mylabel3=tk.Label(top,text="SELECT ENCRYPTION KEY",font=("Arial",8),fg="black",bg="orange",height="3",width="30") #
    #mylabel3.place(x=120, y=300)        

    entry2 = tk.Button(top,font=("Arial",8),text="CLICK HERE TO SELECT ENCRYPTION KEY FILE",width="30",command=lambda:open_aes_key(top))

    entry2.place(x=120, y=300 ,width=300,height=50)        
 
    
    if endpoint==1:
    
        entry3 = tk.Button(top,font=("Arial",8),bg="blue",text="SUBMIT",width="30",command=lambda:des_decryp(top2=top))

        entry3.place(x=160, y=500 ,width=300,height=50)   
    elif endpoint==2:
    
        entry3 = tk.Button(top,font=("Arial",8),bg="blue",text="SUBMIT",width="30",command=lambda:aes_decryp(top2=top))

        entry3.place(x=160, y=500 ,width=300,height=50)   
        
    elif endpoint==3:
    
        entry3 = tk.Button(top,font=("Arial",8),bg="blue",text="SUBMIT",width="30",command=lambda:rsa_decryption(top2=top))

        entry3.place(x=160, y=500 ,width=300,height=50)   
    


'''
def decryption_base2(top):
    global aes_messagefile
    global aes_keyfile   
    
    print(aes_messagefile)
    print(aes_keyfile)
'''















def grsa_encryption(msg,top="",mybutton3="",keysize = 32):
    #print(msg)
    deskey=token_bytes(8)

    e, d, N = generateKeys(keysize)
    
    enc = encrypt(e, N, msg)
    
    keys='e : ' + str(e)+' d : '+ str(d) + ' N : '+str(N)  
    print(str(enc))
    if mybutton3!="":
        mybutton3.destroy()
        
    if top !="":
        timen=datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
    
        mylabel=tk.Label(top,text="RSA ENCRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
        mylabel.place(x=60, y=10)
        
        mylabel2=tk.Label(top,text="ENCRYPTED MESSAGE",font=("Arial",8),fg="black",bg="green",height="3",width="30") #
        mylabel2.place(x=120, y=250)        
    


        entry = tk.Entry(top,font=("Arial",8),width="30")
        entry.insert(0,(str(enc))) 
        entry.place(x=320, y=250 ,width=300,height=50)        



        mylabel2=tk.Label(top,text="ENCRYPTION KEYS",font=("Arial",8),fg="black",bg="darkorange",height="3",width="30") #
        mylabel2.place(x=120, y=350)        
    


        ekey = tk.Entry(top,font=("Arial",8),width="30")
        ekey.insert(0,(str(keys))) 
        ekey.place(x=320, y=350 ,width=300,height=50)     
        f = open('C:/Users/Asus/Downloads/encryption/rsaencryption'+timen, 'w') 
        f.write(enc)
        f.close()     

        temp = {}
        temp['e']=e
        temp['d']=d
        temp['N']=N
        with open('C:/Users/Asus/Downloads/encryption/rsakeys.json'+timen, 'w') as file:
            json_data = json.dumps(temp, indent=4)
            file.write(json_data)
  

    elif top=="":
    
        f = open('C:/Users/Asus/Downloads/encryption/rsaencryption', 'w') 
        f.write(enc)
        f.close()     

        temp = {}
        temp['e']=e
        temp['d']=d
        temp['N']=N
        with open('C:/Users/Asus/Downloads/encryption/rsakeys.json', 'w') as file:
            json_data = json.dumps(temp, indent=4)
            file.write(json_data)




def rsa_decryption(mode=0,top2=""):
    if top2!="":
        top2.destroy()
    if mode==0:
        top=tk.Toplevel()
        top.title("RSA DECRYPTION ")
        top.geometry('1000x800')
        top.configure(background='black')   

        mylabel=tk.Label(top,text="RSA DECRYPTION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
        mylabel.place(x=60, y=10)
        global aes_messagefile
        global aes_keyfile     
        f = open(aes_messagefile, 'rb') 
        message=f.read()
        f.close()
        with open(aes_keyfile) as f:
            keys = json.load(f)    
        e = keys["e"]
        d=keys["d"]
        N = keys["N"]
     
 
    elif mode==1:
        
        f = open('C:/Users/Asus/Downloads/encryption/rsaencryption', 'r') 
        message=f.read()
        
        f.close()    

        with open('C:/Users/Asus/Downloads/encryption/rsakeys.json') as f:
            keys = json.load(f)    
        e = keys["e"]
        d=keys["d"]
        N = keys["N"]
    


    result=decrypt(d, N, message)
    
    if mode==0:
        #print(result)

        mylabel2=tk.Label(top,text="DECRYPTED MESSAGE",font=("Arial",8),fg="black",bg="green",height="3",width="30") #
        mylabel2.place(x=120, y=250)  
        
        entry = tk.Entry(top,font=("Arial",8),width="30")
        entry.insert(0,str(result)) 
        entry.place(x=320, y=250 ,width=300,height=50)  
        mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
        mybutton4.place(x=300, y=400)   


def compare():
    top=tk.Toplevel()
    top.title("COMPARISION")
    top.geometry('1000x800')
    top.configure(background='black')

        
    mylabel=tk.Label(top,text="COMPARISION",font=("Arial",14),fg="white",bg="brown",height="3",width="60") #
    mylabel.place(x=60, y=10)
    
    mylabel2=tk.Label(top,text="ENTER MESSAGE FOR ENCRYPTION",font=("Arial",8),fg="black",bg="orange",height="3",width="30") #
    mylabel2.place(x=120, y=250)        

    entry = tk.Entry(top,font=("Arial",8),width="30")
    entry.insert(0,"") 


    entry.place(x=320, y=250 ,width=300,height=50)        


    mybutton3=tk.Button(top,text="ENCRYPT & COMPARE",font=("Arial",8),fg="white",bg="green",height="3",width="30",command=lambda: gcompare(entry.get(),top,mybutton3))
    mybutton3.place(x=300, y=400)
    
    

    mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
    mybutton4.place(x=300, y=610)     


def gcompare(msg,top,mybutton3):

    start_time =  timeit.default_timer()
    
    
    (grsa_encryption(msg))
    rsa_encryptiontime=(timeit.default_timer() - start_time)
    start_time2 =  timeit.default_timer()
    rsa_decryption(mode=1)
    rsa_decryptiontime=( timeit.default_timer() - start_time2)
    


    print('rsa enctime',rsa_encryptiontime)
    print('rsa dec time',rsa_decryptiontime)

    start_time3 = timeit.default_timer()

    (gaes_encryption(msg))
    aes_encryptiontime=(timeit.default_timer()  - start_time3)
    
    start_time4 =  timeit.default_timer()
    aes_decryp(mode=1)
    aes_decryptiontime=( timeit.default_timer() - start_time4)

    print('aes enctime',aes_encryptiontime)
    print('aes dec time',aes_decryptiontime)
    

    start_time5 =  timeit.default_timer()
    (gdes_encryption(msg))
    des_encryptiontime=( timeit.default_timer() - start_time5)
    start_time6 =timeit.default_timer() 
    des_decryp(mode=1)
    des_decryptiontime=( timeit.default_timer() - start_time6)

    print('des enctime',des_encryptiontime)
    print('des dec time',des_decryptiontime)


    plot_comparision([des_encryptiontime*1000,aes_encryptiontime*1000,rsa_encryptiontime*1000],[des_decryptiontime*1000,aes_decryptiontime*1000,rsa_decryptiontime*1000])



    mybutton4=tk.Button(top,text="EXIT",font=("Arial",8),fg="white",bg="blue",height="3",width="30",command=top.destroy)
    mybutton4.place(x=300, y=610)         
    
    
    
    






class FirstPage(tk.Frame):
    def __init__(self, parent, controller,):
    
    
    
        tk.Frame.__init__(self, parent, bg="black")
        
    


        load = Image.open("C:/Users/Asus/Downloads/encryption/img3.jpg")
        photo = ImageTk.PhotoImage(load)
        label = tk.Label(self, image=photo)
        label.image=photo
        label.place(x=0,y=0)

        mylabel=tk.Label(self,text="Select Operation",font=("Arial",14),fg="white",bg="brown",height="3",width="45") #
        mylabel.place(x=160, y=20)
        


        mybutton2=tk.Button(self,text="AES",font=("Arial",11),fg="white",bg="red",height="3",width="40",command=lambda:controller.show_frame(ASecondPage))
        mybutton2.place(x=230, y=150)
        
        
        
        mybutton1=tk.Button(self,text="DES",font=("Arial",11),fg="white",bg="orange",height="3",width="40",command=lambda:controller.show_frame(DSecondPage))
        mybutton1.place(x=230, y=280)
        
 
        #,command=grapher

        mybutton3=tk.Button(self,text="RSA",font=("Arial",11),fg="white",bg="green",height="3",width="40",command=lambda: controller.show_frame(RSecondPage))
        mybutton3.place(x=230, y=410)




        mybutton4=tk.Button(self,text="COMPARE",font=("Arial",11),fg="white",bg="blue",height="3",width="40",command=lambda:compare())
        mybutton4.place(x=230, y=540)        


        #mybutton5=tk.Button(self,text="EXIT",font=("Arial",11),fg="white",bg="red",height="3",width="40",command=self.destroy)
        #mybutton5.place(x=230, y=660)   
        
        
class ASecondPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="black")
        
        load = Image.open("C:/Users/Asus/Downloads/encryption/img4.jpg")
        photo = ImageTk.PhotoImage(load)
        label = tk.Label(self, image=photo)
        label.image=photo
        label.place(x=0,y=0)
        
        
        mylabel=tk.Label(self,text="Select Operation For AES",font=("Arial",14),fg="white",bg="brown",height="3",width="45") #
        mylabel.place(x=160, y=15)
        


        mybutton2=tk.Button(self,text="ENCRYPT",font=("Arial",11),fg="white",bg="red",height="3",width="40",command=lambda:aes_encryp())
        mybutton2.place(x=230, y=160)
        

        #aes_decryp()
        mybutton1=tk.Button(self,text="DECRYPT",font=("Arial",11),fg="white",bg="orange",height="3",width="40",command=lambda:decryptor_base(2))
        mybutton1.place(x=230, y=310)
        
        
        

        



        #,command=grapher
       
        mybutton4=tk.Button(self,text="HOME",font=("Arial",11),fg="white",bg="blue",height="3",width="40",command=lambda:controller.show_frame(FirstPage))
        mybutton4.place(x=230, y=610)        
        
        
class RSecondPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="black")

        load = Image.open("C:/Users/Asus/Downloads/encryption/img4.jpg")
        photo = ImageTk.PhotoImage(load)
        label = tk.Label(self, image=photo)
        label.image=photo
        label.place(x=0,y=0)
        
        mylabel=tk.Label(self,text="Select Operation For RSA",font=("Arial",14),fg="white",bg="brown",height="3",width="45") #
        mylabel.place(x=160, y=15)
        


        mybutton2=tk.Button(self,text="ENCRYPT",font=("Arial",11),fg="white",bg="red",height="3",width="40",command=lambda: (rsa_encryp () ))
        mybutton2.place(x=230, y=160)
        

        

        mybutton1=tk.Button(self,text="DECRYPT",font=("Arial",11),fg="white",bg="orange",height="3",width="40",command=lambda:decryptor_base(3))
        mybutton1.place(x=230, y=310)
        
        



        #,command=grapher

       
        mybutton4=tk.Button(self,text="HOME",font=("Arial",11),fg="white",bg="blue",height="3",width="40",command=lambda:controller.show_frame(FirstPage))
        mybutton4.place(x=230, y=610)        
        
        
 
        
        
class DSecondPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="black")
        load = Image.open("C:/Users/Asus/Downloads/encryption/img4.jpg")
        photo = ImageTk.PhotoImage(load)
        label = tk.Label(self, image=photo)
        label.image=photo
        label.place(x=0,y=0)
        
        mylabel=tk.Label(self,text="Select Operation For DES",font=("Arial",14),fg="white",bg="brown",height="3",width="45") #
        mylabel.place(x=160, y=15)
        


        mybutton2=tk.Button(self,text="ENCRYPT",font=("Arial",11),fg="white",bg="red",height="3",width="40",command=lambda:des_encryp())
        mybutton2.place(x=230, y=160)
        


        mybutton1=tk.Button(self,text="DECRYPT",font=("Arial",11),fg="white",bg="orange",height="3",width="40",command=lambda:decryptor_base(1))
        mybutton1.place(x=230, y=310)



        #,command=grapher
       
        mybutton4=tk.Button(self,text="HOME",font=("Arial",11),fg="white",bg="blue",height="3",width="40",command=lambda:controller.show_frame(FirstPage))
        mybutton4.place(x=230, y=610)        
          
     
        
        
        
class Application(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        
        #creating a window
        window = tk.Frame(self)
        window.pack()
        
        window.grid_rowconfigure(0, minsize = 1000)
        window.grid_columnconfigure(0, minsize = 800)
        
        self.frames = {}
        for F in (FirstPage, ASecondPage,DSecondPage,RSecondPage):
        
            frame = F(window, self)
            
            self.frames[F] = frame
            frame.grid(row = 0, column=0, sticky="nsew")
            
        self.show_frame(FirstPage)
        
    def show_frame(self, page):
        frame = self.frames[page]
        frame.tkraise()
        self.title("Encryptor")

app = Application()
app.maxsize(1000,800)
app.mainloop()
