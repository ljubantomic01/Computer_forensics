import magic
import hashlib
import glob

1)
file1 = magic.from_file("./file1")
file2 = magic.from_file("./file2.txt")
file3 = magic.from_file("./file3")

print(f"File1 extension: {file1}")
print(f"File2 extension: {file2}")
print(f"File3 extension: {file3}")

2)
with open("test.txt", "r") as file:
    message = file.read().encode()
    print("MD5: ", hashlib.md5(message).hexdigest())
    print("SHA1: ", hashlib.sha1(message).hexdigest())
    print("SHA256: ", hashlib.sha256(message).hexdigest())

with open("test1.txt", "r") as file:
    message = file.read().encode()
    print("MD5: ", hashlib.md5(message).hexdigest())
    print("SHA1: ", hashlib.sha1(message).hexdigest())
    print("SHA256: ", hashlib.sha256(message).hexdigest())

3)
    # a)
print("\nDIGEST .docx:")
with open("test.docx", "rb") as file:
    message = file.read()
    print("MD5: ", hashlib.md5(message).hexdigest())
    print("SHA1: ", hashlib.sha1(message).hexdigest())
    print("SHA256: ", hashlib.sha256(message).hexdigest())

print("DIGEST .jpg:")
with open("test.jpg", "rb") as file:
    message = file.read()
    print("MD5: ", hashlib.md5(message).hexdigest())
    print("SHA1: ", hashlib.sha1(message).hexdigest())
    print("SHA256: ", hashlib.sha256(message).hexdigest())

    # b)
hash = "c15e32d27635f248c1c8b66bb012850e5b342119"

filenames = glob.glob("./Dokaz/*")

for fileName in filenames:
    with open(fileName, "rb") as file:
        message = file.read()
        if hash == hashlib.sha1(message).hexdigest():
            print(f"Trazeni dokument : {fileName}")
            fileExtension = magic.from_file(fileName)
            print(f"{fileName} extension: {fileExtension}")
