import os
import sys
import optparse
from exif import Image
import webbrowser
from PyPDF2 import PdfFileReader, PdfFileWriter


def convertGPScoordinate(coordinate, coordinate_ref):
    decimal_degrees = coordinate[0] + \
        coordinate[1] / 60 + \
        coordinate[2] / 3600

    if coordinate_ref == "S" or coordinate_ref == "W":
        decimal_degrees = -decimal_degrees

    return decimal_degrees


def figMetaData(file_path):
    img_doc = Image(open(file_path, "rb"))
    coordinates = []

    if not img_doc.has_exif:
        sys.exit(f"Image does not contain EXIF data.")
    else:
        print(f"Image contains EXIF (version {img_doc.exif_version}) data.")

    print(f"{dir(img_doc)}\n")
    coordinates.append(convertGPScoordinate(
        img_doc.gps_latitude, img_doc.gps_latitude_ref))
    coordinates.append(convertGPScoordinate(
        img_doc.gps_longitude, img_doc.gps_longitude_ref))
    openBrowser(coordinates[0], coordinates[1])


def openBrowser(lat, long):
    url = f"http://www.google.com/maps/place/{lat},{long}"
    webbrowser.open_new_tab(url)


def pdfMetaData(file_path):
    pdf_doc = PdfFileReader(open(path, "rb"))
    if pdf_doc.isEncrypted:
        try:
            if pdf_doc.decrypt("banana") != 1:
                sys.exit("target pdf document is encrypted")
        except:
            sys.exit("target pdf document is encrypted")

    pdfWriter = PdfFileWriter()
    for pageNum in range(pdf_doc.numPages):
        pdfWriter.addPage(pdf_doc.getPage(pageNum))
    resultPdf = open('decrypted_output.pdf', 'wb')
    pdfWriter.write(resultPdf)
    resultPdf.close()


if __name__ == "__main__":
    parser = optparse.OptionParser("Usage: python <script_name> -f <file>")
    parser.add_option("-f", dest="file", type="string",
                      help="please provide full path to the document")

    (options, args) = parser.parse_args()

    path = options.file
    if not path:
        print("please provide full path to the document")
        sys.exit(parser.usage)

    if any(path.endswith(ext) for ext in (".jpg", ".bmp", ".jpeg",)):
        figMetaData(path)
    if path.endswith(".pdf"):
        pdfMetaData(path)
    else:
        print("File extension not supported/recognized... Make sure the file has the correct extension...")
