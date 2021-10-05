#This is a program that generates public key information and a message and encrypts it using RSA cipher algorithms
#This program will also allow for decryption using a private key and the adding of signatures
#Ian Fields, Ana Cortez, Noah Burgin
#Algorithms 3330, 9/21/2021

import math

chara = []
auth = []

#Public Key Generation
#Uses Euclid's Algorithm
def pubKeyGen(p,q):
   n = p*q
   e = 0
   phi = (p-1)*(q-1)

   for x in range(phi):
       if(math.gcd(x,phi) == 1 and x > 1):
          e = x
          break
   return(e,n,phi)

#Message Encryption
#Uses Fast Modular Exponentiation Algorithm
def rsaEncryption(message, e, n):
    encMessage = ""
    for x in message: 
        x = pow(ord(x), e, n)
        chara.append(x)
        encMessage += str(x)
    return(encMessage)

#Signature Encryption
#Uses Fast Modular Exponentiation Algorithm
def sigEncryption(sig,d,n):
    for x in sig:
        x = pow(ord(x),d,n)
        auth.append(x)

#Message Decryption
#Uses Fast Modular Exponentiation Algorithm
def rsaDecryption(d, n):
    message = ""
    for x in chara:
        x = pow(x,d,n)
        message += chr(x)
    return(message)

#Signature Decryption
#Uses Fast Modular Exponentiation Algorithm
def sigDecryption(e, n):
    name = ""
    for x in auth:
        x = pow(x,e,n)
        name += chr(x)
    return(name)

#Private Key Generation
#Uses Extended Euclid's algorithm
def modinv(e, phi):
    d_old = 0; r_old = phi
    d_new = 1; r_new = e
    while r_new > 0:
        a = r_old // r_new
        (d_old, d_new) = (d_new, d_old - a * d_new)
        (r_old, r_new) = (r_new, r_old - a * r_new)
    return d_old % phi if r_old == 1 else None

#Tests
def test():
    print("\t\t**Test Cases **\n")
    print("Tests using p = 7 and q = 17")
    e,n,phi = pubKeyGen(7,17)
    print("E is : " + str(e))
    print("N is : " + str(n))
    print("Phi is : " + str(phi))
    print("E and Phi's GCD is : " + str(math.gcd(e,phi)))
    print("The public key is : (" + str(e) + "," + str(n) + ")")
    d = modinv(e, phi)
    print("The private key is : " + str(d))
    print("The statement \"Hello\" encrypted is : " + rsaEncryption("Hello", e, n))
    print("The statement decrypted is : " + rsaDecryption(d,n))

    for x in range(len(chara)):
        chara.pop()

def main():
   test()
   p = 588173
   q = 961811
   n = 0
   phi = 0
   e = 0
   d = 0
   a = 0
   b = 0
   digSig = ""
   digSigVeri = ""
   digSigEncrypted = ""
   outerEnd = False

   #General text UI, recieves the message to be either encrypted or decrypted
   while(outerEnd == False):

       print("\n")
       print("Welcome to the RSA encryption/decryption generator for Algo 3330")
       print("What is your current user status? (O for key owner, or G for General User): ")
       userStatus = input().upper()

       #General User
       if (userStatus == "G"):
           innerEnd = False

           while(innerEnd == False):
               print("\n")

               #The program path for a general user, giving them the option to encrypt a message or authenticate a potential owner's digital signature.
               print("General User has been selected. Would you like to encrypt a message or authenticate a digital signature?")
               genUserAction = input("Enter E for encryption or A for signature authentication: ").upper()

               #Encryption
               if (genUserAction == 'E'):
                   for x in range(len(chara)):
                       chara.pop()
                   print("Encryption has been selected.")
                   message = input("Please input your message to be encrypted: ")
                   e,n,phi = pubKeyGen(p,q)
                   print("The encrypted message is : " + rsaEncryption(message, e, n))
               
               #Authentication
               elif (genUserAction == 'A'):
                   print("Signature Authentication has been selected.")
                   e,n,phi = pubKeyGen(p,q)
                   digSigEncrypted = sigDecryption(e,n)
                   if (digSig == digSigEncrypted):
                       print("Signature verified.")
                   else:
                       print("Signature could not be verified.")

               #Continuation Question
               continueQuestion = input("To perform another task input Y for yes or N for no : ").upper()
               if(continueQuestion == "Y"):
                   continueQuestion = input("Would you like to switch user status? Input Y for yes or N for no : ").upper()
                   if(continueQuestion == "Y"):
                       innerEnd = True
               else:
                    outerEnd = True
                    innerEnd = True
       
       #Key Owner
       elif (userStatus == "O"):
           innerEnd = False

           while(innerEnd == False):
               print("\n")

               #The program path for the Key Owner, gives the option to Encrypt then Decrypt a message and add a digital signature.
               print("Key Owner has been selected")

               #Encryption/Decryption
               question = input("If a message has already been encrypted enter Y or if a message needs to be encrypted enter N: ").upper()
               if(question == "N"):
                   for x in range(len(chara)):
                       chara.pop()
                   message = input("Enter message to be encrypted then decrypted: ")
                   e,n,phi = pubKeyGen(p,q)
                   print("The encrypted message is : " + rsaEncryption(message, e, n))
                   d = modinv(e,phi)
                   print("The decrypted message is : " + rsaDecryption(d, n))
               if(question == "Y"):
                   e,n,phi = pubKeyGen(p,q)
                   print("The encrypted message is : " + str(chara))
                   d = modinv(e,phi)
                   print("The decrypted message is : " + rsaDecryption(d,n))
               
               #Digital Signature
               print("Would you like to add a digital signature to your message?")
               sigOrNo = input("Y for yes or N for no: ").upper()

               if (sigOrNo == "Y"):
                   digSig = input("Enter your name here: ")
                   sigEncryption(digSig,d,n)    
               else:
                   digSig = None
               
               #Continuation Question
               continueQuestion = input("To perform another task input Y for yes or N for no : ").upper()
               if(continueQuestion == "Y"):
                   continueQuestion = input("Would you like to switch user status? Input Y for yes or N for no : ").upper()
                   if(continueQuestion == "Y"):
                       innerEnd = True
               else:
                   outerEnd = True
                   innerEnd = True
 

if __name__ == "__main__":
    main()

