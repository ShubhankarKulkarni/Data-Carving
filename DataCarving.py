import os
import sys
import hashlib


#this function creates a hash of a given file and store it in hash.txt
def save_hash_to_file(recovered_file):
    hash_recovered_file = hashlib.md5()
    with open(os.path.join("Shubhankar", recovered_file), "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_recovered_file.update(chunk)
    hash_of_file = hash_recovered_file.hexdigest() #create a hash
    with open(os.path.join("Shubhankar", "hash.txt"), "a") as hash_file:
        hash_file.write(recovered_file+ ":\n")
        hash_file.write(hash_of_file+"\n\n")#Store in hash.txt under Shubhankar Directory


#this functions take written arguments and carves the files based on input
#sof: Start of File Bytes
#eof: End of File Bytes
#sof_mem_bytes: Number of Bytes in sof
#eof_mem_bytes: Number of Bytes in eof
#output_file_type: File type that needs to be carved
def detect_files(data, file_name, sof, eof, sof_mem_bytes, eof_mem_bytes, output_file_type):
    with open(file_name, "rb") as binary_file:
        #sof_stack: this is a list used as a stack in the program that stores all the sof
        #this is useful in carving the files hidden inside other files
        sof_stack = list()
        memory_counter = 0 #points to current memory location
        file_byte = binary_file.read(1)
        while file_byte:
            file_byte = binary_file.read(1)
            memory_counter = memory_counter + 1
            probable_sof = data[memory_counter : memory_counter + sof_mem_bytes]
            probable_eof = data[memory_counter : memory_counter + eof_mem_bytes]
            if probable_sof == sof:#checks for whole chunk selected in memory with provided sof
                sof_stack.append(memory_counter)#if matched, adds memory location to sof stack
            if probable_eof == eof:#checks for whole chunk selected in memory with the provided eof
                #if there is no sof found in memory, finding eof makes no sense
                #if sof is found but eof is less than last sof then also it makes no sense
                #these two conditions are checked below
                if len(sof_stack) is not 0 and sof_stack[len(sof_stack)-1] < memory_counter:
                    #below command takes a data from sof to eof and stores in file_data
                    file_data = data[sof_stack[len(sof_stack)-1]:memory_counter + eof_mem_bytes]
                    #file name is constructed with sof memory location, eof memory location and provided type
                    Recovered_file_name = "Recovered_{}_{}.{}".format(sof_stack[len(sof_stack)-1], memory_counter + eof_mem_bytes, output_file_type)
                    with open(os.path.join("Shubhankar", Recovered_file_name), "wb") as recovered_file:
                        recovered_file.write(file_data)#stores recovered data in file
                        recovered_file.close()
                    save_hash_to_file(Recovered_file_name)#calculate hash and store in hash.txt
                    sof_stack.pop(len(sof_stack)-1)#remove last appended element from sof stack
                    print("Carved file {} with file size {} Bytes".format(Recovered_file_name, os.path.getsize("Shubhankar/"+Recovered_file_name)))


def detect_pdf_files(data, file_name):
    sof = b'\x25\x50\x44\x46'
    sof_mem_bytes = 4
    output_file_type = "pdf"
    eof_variety = {b'\x0A\x25\x25\x45\x4F\x46': 6, b'\x0A\x25\x25\x45\x4F\x46\x0A': 7, b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A': 9 ,b'\x0D\x25\x25\x45\x4F\x46\x0D': 7}
    for eof, eof_mem_bytes in eof_variety.items():
        detect_files(data, file_name, sof, eof, sof_mem_bytes, eof_mem_bytes, output_file_type)


def detect_png_files(data, file_name):
    sof = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
    eof = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
    sof_mem_bytes = 8
    eof_mem_bytes = 8
    output_file_type = "png"
    detect_files(data, file_name, sof, eof, sof_mem_bytes, eof_mem_bytes, output_file_type)  


def detect_docx_files(data, file_name):
    sof = b'\x50\x4B\x03\x04\x14\x00\x06\x00'
    eof = b'\x50\x4B\x05\x06'
    sof_mem_bytes = 8
    eof_mem_bytes = 4
    output_file_type = "docx"
    detect_files(data, file_name, sof, eof, sof_mem_bytes, eof_mem_bytes, output_file_type)


def detect_jpeg_files(data, file_name):
    sof = b'\xff\xd8\xff'
    eof = b'\xff\xd9'
    sof_mem_bytes = 3
    eof_mem_bytes = 2
    output_file_type = "jpg"
    detect_files(data, file_name, sof, eof, sof_mem_bytes, eof_mem_bytes, output_file_type)            


#this function reads a binary file and stores its data for further use
def read_file(file_name):
	if os.path.isfile(file_name):
		with open(file_name, "rb") as binary_file:
			data = binary_file.read()
			binary_file.close()
		return data
	else:
		print("File not found")
		exit()


def take_input():
    file_name = sys.argv[1]
    if not os.path.isdir("Shubhankar"):
        os.mkdir("Shubhankar")
    data = read_file(file_name) 
    #following functions provide signature of respective files to detect_files function
    detect_png_files(data, file_name)   
    detect_jpeg_files(data, file_name)
    detect_pdf_files(data, file_name)
    detect_docx_files(data, file_name)


if __name__ == "__main__":
    take_input()
