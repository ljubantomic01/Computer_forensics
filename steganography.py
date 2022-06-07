# Steganografija po tehnici LSB - Least Significant Bit
#Umetanje slike ili teksta u sliku

from fileinput import filename
import cv2
import numpy as np
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# 1. korak - funkcija koja će konvertirati podatke u binarni oblik

# Funkcija pretvara podatke u binary stringove
# 08b ->  to znači da pretvara u string bitova duljine 8 = byte, 
# inače bi npr. 6 bilo 110, umjesto 00000110
# ord(i) vraća Unicode code za neki karakter
# .join -> na argument dodaj ono ispred join

#funkcija za derivanje key iz passworda
def derive_key(key_seed: str) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b'',
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key

def convert_to_binary(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [ format(i, "08b") for i in data ]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format (data, "08b")
    else:
        raise TypeError(" This type of data is not supported!\n")

# 2. korak - napravit funkciju za enkodiranje podataka

def encode(image_name, secret_data):
    # prvo učitavamo sliku
    image  = cv2.imread(image_name)

    # računamo koliko slobodnih bajta imamo za pohranu podataka u sliku
    # image.shape sadrži dimenzije slike * 3 kanala / 8 bitova
    max_bytes = image.shape[0] * image.shape[1] * 3 // 8
    print(" Max bytes to encode : ", max_bytes)
    
    # ograničenje za pohranu podataka
    if len(secret_data) > max_bytes:
        raise ValueError(" Too much data for this image;\nUse BIGGER IMAGE or LESS DATA!\n")

    print(" Encoding sercret data into image...")
    
    # ovime označavamo di je kraj
    secret_data += "====="

    # index koji "šetamo" po secret_data
    data_index = 0

    binary_sec_data = convert_to_binary(secret_data)
    data_length = len(binary_sec_data)

    for row in image:
        for pixel in row:
            # RGB vrijednosti u binarne
            r,g,b = convert_to_binary(pixel)

            # uvjet da još ima podataka za spremanje
            if data_index < data_length:

                # prvi dio piksela je kakav je i bio samo se na zadnji doda bit iz secret_data
                # tako za crveni, zeleni i plavi dio piksela respektivno
                pixel[0] = int(r[:-1] + binary_sec_data[data_index], 2)
                data_index += 1
            
            if data_index < data_length:
                pixel[1] = int(g[:-1] + binary_sec_data[data_index], 2)
                data_index += 1
            
            if data_index < data_length:
                pixel[2] = int(b[:-1] + binary_sec_data[data_index], 2)
                data_index += 1
            
            if data_index >= data_length:
                break

    return image

# 3. korak - napravit funckije za dekodiranje
def decode (image_name):
    print(" Decoding secret data from image...")

    image = cv2.imread(image_name)
    
    binary_result = ""
    decoded_data = ""

    for row in image:
        for pixel in row:
            r,g,b = convert_to_binary(pixel)

            # dodajemo zadnji bit (znak) svakog od komponenti piksela
            binary_result += r[-1]
            binary_result += g[-1]
            binary_result += b[-1]
    
    # pretvaramo rezultat u bajtove
    # range(start, stop, step)
    bytes_result = [ binary_result[i:i+8] for i in range (0, len(binary_result), 8)]

    # izdvajamo znak iz svakog bajta koji smo dobili
    for byte in bytes_result:
        decoded_data += chr(int(byte, 2))
       
        # provjera jel od 5og elementa odzada do kraja ovaj string
        # i ako je, prestajemo s dekodiranjem
        if decoded_data[-5:] == "=====":
            break
    # vraćamo sve od početka do 5og elementa odzada
    return decoded_data[:-5]

def get_f_key():
    #derivamo key iz passworda
    print("Password : ")
    password = input()
    key =  base64.b64encode(derive_key(password))
    f = Fernet(key)

    return f

def choice_fun():

    while (True):

        # biramo što želimo enkodirati u sliku
        print(" What would you like to encode/decode - text (T) or image (I) : ")
        object_choice = input()

        if object_choice == 'T' or object_choice == 't':

            print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
            choice = input()
            
            while(True):
                if choice == 'E' or choice == 'e':
                    choice_encode_text()
                    choice = input()
                
                elif choice == 'D' or choice == 'd':
                    choice_decode_text()
                    choice = input()
                
                elif choice == "C" or choice == 'c':
                    print(" Canceling TEXT mode... \n")
                    break

                elif choice == "S" or choice == 's':
                    print("Program is stopping with execution...")
                    print("Done!")
                    return
                
                else: 
                    print(" You can choose either E, D, C or S!!! \n")
                    print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
                    choice = input()

        elif object_choice == 'I' or object_choice == 'i':
            print(" Type E for encode, D for decode, C for canceling image mode or S to stop program : ")
            choice = input()

            while(True):
                if choice == 'E' or choice == 'e':
                    choice_encode_image()
                    choice = input()
                
                elif choice == 'D' or choice == 'd':
                    choice_decode_image()
                    choice = input()
                
                elif choice == "C" or choice == 'c':
                    print(" Canceling IMAGE mode... \n")
                    break

                elif choice == "S" or choice == 's':
                    print("Program is stopping with execution...")
                    print("Done!")
                    return
                
                else: 
                    print(" You can choose either E, D, C or S!!! \n")
                    print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
                    choice = input()
            
        else:
            print("You can type T or I !!!")
            print(" What would you like to encode/decode - text (T) or image (I) : ")
            object_choice = input()
                

def choice_encode_text():
    
    # slika nositelj teksta
    print(" Input image name : ")
    input_image = input()
    if input_image[-4:] != ".png":
        input_image += ".png"

    # ime stego slike
    print(" Output image name : ")
    output_image = input()
    if output_image[-4:] != ".png":
        output_image += ".png"
    
    while(True):
        # biramo je li tekst s tipkovnice ili iz datoteke
        print(" Text source : file or plaintxt ?")
        source = input()
        if source == "file":
            print(" File name : ")
            file_name = input()
            if file_name[-4:] != ".txt":
                file_name += ".txt"
            
            # čitanje u binarnom modu
            with open(file_name, "rb") as file:
                secret_data = file.read()
            break
        elif source == "plaintxt":
            print(" Message to encode :")
            secret_data = input().encode()
            break
        else :
                print(" Text source : file or plaintxt ?")
                source = input()
        
    f = get_f_key()
    # enkripcija podataka
    # decode sluzi za pretvaranje u string kako bi ga mogao korititi encode()
    encrypted_secret_data = f.encrypt(secret_data).decode()
    encoded_image = encode(image_name = input_image, secret_data = encrypted_secret_data)
        
    # ime slike, koja slika se sprema pod tim imenom
    cv2.imwrite(output_image, encoded_image)
    print(" Encoding is done!\n")
    print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
    return 

def choice_decode_text():

    # ime slike koju želimo dekodirati i izvući tekst
    print(" Image to decode : ")
    output_image = input()
    if output_image[-4:] != ".png":
        output_image += ".png"
    
    #unošenje passworda kako bi se dobio ključ za dekripciju
    f = get_f_key()

    decoded_data = decode(output_image)

    # dodajemo jer se kod decode() izgubi 
    decoded_data += "=="
    # dekriptiranje izvučenih podataka, encode pretvara u bytove radi dekripcije, a decode u string
    decrypted_data = f.decrypt(decoded_data.encode())
    print(" Decryped data : \n", decrypted_data.decode() )
    print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
    return

def choice_encode_image():

    # slika nositelj
    print(" Input image name : ")
    input_image = input()
    if input_image[-4:] != ".png":
        input_image += ".png"

    # slika koju želimo sakriti
    print(" Secret image : ")
    secret_image = input()
    if secret_image[-4:] != ".png":
        secret_image += ".png"
    
    # čitaj datoteku u binarnom modu
    with open(secret_image, "rb") as image2string:
        secret_data = base64.b64encode(image2string.read()).decode()

    encoded_image = encode(image_name = input_image, secret_data = secret_data)
        
    # ime slike, koja slika se sprema pod tim imenom
    cv2.imwrite("encoded_image.png", encoded_image)
    print(" Encoding is done!\n")
    print(" Your encoded_image.png is ready to use!")    
    print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
    return 

def choice_decode_image():

    # slika koju želimo dekodirati
    print(" Image to decode : ")
    output_image = input()
    if output_image[-4:] != ".png":
        output_image += ".png"

    decoded_data = decode(output_image)
    decoded_data += "=="

    # pisi u datoteku u binarnom modu
    decodeit = open('source_image.png', 'wb')
    decodeit.write(base64.b64decode((decoded_data.encode())))
    decodeit.close()

    print(" Your source_image.png is extracted and ready to use!")    
    print(" Type E for encode, D for decode, C for canceling text mode or S to stop program : ")
    return 
        
if __name__ == "__main__":

    choice_fun()
    
        
# ctrl + K + C - multiline commenting







    






            


