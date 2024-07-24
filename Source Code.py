from PIL import Image #image manipulation
import os.path
from os import path
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from colorama import init
from termcolor import cprint 
from pyfiglet import figlet_format
from rich import print
from rich.console import Console
from rich.table import Table
import os
import getpass
from rich.progress import track
import sys

console = Console()
headerText = "M6nMjy5THr2J"


def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate Initialization vector
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode() if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the Initialization vector from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def convertToRGB(img):
	try:
		rgba_image = img
		rgba_image.load()
		background = Image.new("RGB", rgba_image.size, (255, 255, 255))
		background.paste(rgba_image, mask = rgba_image.split()[3])
		print("[yellow]Converted image to RGB [/yellow]")
		return background
	except Exception as e:
		print("[red]Couldn't convert image to RGB [/red]- %s"%e)


def getPixelCount(img):
	width, height = Image.open(img).size
	return width*height


def encodeImage(image,message,filename):
	with console.status("[green]Encoding image..") as status:
		try:
			width, height = image.size
			pix = image.getdata()

			current_pixel = 0 #start from beginning
			tmp=0 #counter

			x=0
			y=0
			for ch in message:
				binary_value = format(ord(ch), '08b')
				
				# For each character, get 3 pixels at a time
				p1 = pix[current_pixel]
				p2 = pix[current_pixel+1]
				p3 = pix[current_pixel+2]

				three_pixels = [val for val in p1+p2+p3] #make them as one list

				for i in range(0,8):
					current_bit = binary_value[i]

					# 0 - Even
					# 1 - Odd
					if current_bit == '0':
						if three_pixels[i]%2!=0:
							three_pixels[i]= three_pixels[i]-1 if three_pixels[i]==255 else three_pixels[i]+1
					elif current_bit == '1':
						if three_pixels[i]%2==0:
							three_pixels[i]= three_pixels[i]-1 if three_pixels[i]==255 else three_pixels[i]+1

				current_pixel+=3 #take next set of pixels
				tmp+=1 #increment counter

				#Set 9th value
				if(tmp==len(message)):
					# Make as 1 (odd) - stop reading
					if three_pixels[-1]%2==0:
						three_pixels[-1]= three_pixels[-1]-1 if three_pixels[-1]==255 else three_pixels[-1]+1
				else:
					# Make as 0 (even) - continue reading
					if three_pixels[-1]%2!=0:
						three_pixels[-1]= three_pixels[-1]-1 if three_pixels[-1]==255 else three_pixels[-1]+1


				three_pixels = tuple(three_pixels)
				
				st=0
				end=3

				for i in range(0,3): #modifying pixels 
					image.putpixel((x,y), three_pixels[st:end])
					st+=3
					end+=3

					if (x == width - 1):
						x = 0
						y += 1
					else:
						x += 1

			encoded_filename = filename.split('.')[0] + "-enc.png"
			image.save(encoded_filename)
			print("\n")
			print("[yellow]Original File: [u]%s[/u][/yellow]"%filename)
			print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]"%encoded_filename)

		except Exception as e:
			print("[red]An error occured - [/red]%s"%e)
			sys.exit(0)



def decodeImage(image):
	with console.status("[green]Decoding image..") as status:
		try:
			pix = image.getdata()
			current_pixel = 0
			decoded=""
			while True:
				# Get 3 pixels each time
				binary_value=""
				p1 = pix[current_pixel]
				p2 = pix[current_pixel+1]
				p3 = pix[current_pixel+2]
				three_pixels = [val for val in p1+p2+p3] #make them as one list

				for i in range(0,8):
					if three_pixels[i]%2==0:
						# add 0 to msg
						binary_value+="0"
					elif three_pixels[i]%2!=0:
						# add 1 to msg
						binary_value+="1"


				#Convert binary value to ascii and add to string
				binary_value.strip() #strip removes spaces
				ascii_value = int(binary_value,2)
				decoded+=chr(ascii_value)
				current_pixel+=3

				if three_pixels[-1]%2!=0:
					#last letter termination
					break

			# print("Decoded: %s"%decoded)
			return decoded
		except Exception as e:
			print("[red]An error occured - [/red]%s"%e)
			sys.exit()


def print_credits():
	table = Table(show_header=True)
	table.add_column("Name",style="yellow")
	table.add_column("Roll Number",style="yellow")
	table.add_row("Sameekruth", "160121771063")
	table.add_row("Mushtaq", "160121771050")
	table.add_row("Prashanth", "160121771051")
	table.add_row("Pavan", "160121771062")
	console.print(table)


def main():

	print("[cyan]Choose one: [/cyan]")
	op = int(input("1. Encode\n2. Decode\n>>"))

	if op==1:
		print("[cyan]Image path (with extension): [/cyan]")
		img = input(">>")
		if(not(path.exists(img))):
			raise Exception("Image not found!")

		
		print("[cyan]Message to be hidden: [/cyan]")
		message = input(">>")
		message = headerText + message #add header to message to prevent checking of non encrypted images
		if((len(message)+len(headerText))*3 > getPixelCount(img)):
			raise Exception("Given message is too long to be encoded in the image.")


		password=""
		while 1:
			print("[cyan]Password to encrypt: [/cyan]")
			password = getpass.getpass(">>") #getpass module doesnt show pswrd while typing
			if password=="":
				break
			print("[cyan]Re-enter Password: [/cyan]")
			confirm_password = getpass.getpass(">>")
			if(password!=confirm_password):
				print("[red]Passwords don't match try again [/red]")
			else:
				break

		cipher=""
		if password!="":
			cipher = encrypt(key=password.encode(),source=message.encode())
			cipher = headerText + cipher # Add header to cipher
		else:
			cipher = message

		image = Image.open(img)
		print("[yellow]Image Mode: [/yellow]%s"%image.mode)
		if image.mode!='RGB':
			image = convertToRGB(image)
		newimg = image.copy()
		encodeImage(image=newimg,message=cipher,filename=image.filename)
		print()
		wait=input("Press Any Key To Exit\n") #doesn't close terminal after execution

	elif op==2:
		print("[cyan]Image path (with extension): [/cyan]")
		img = input(">>")
		if(not(path.exists(img))):
			raise Exception("Image not found!")

		print("[cyan]Enter password: [/cyan]")
		password = getpass.getpass(">>")

		image = Image.open(img)

		cipher = decodeImage(image)


		header = cipher[:len(headerText)]

		if header.strip()!=headerText: #match header with decrypted text
			print("[red]Invalid data![/red]")
			sys.exit(0)


		print()

		decrypted=""

		if password!="":
			cipher = cipher[len(headerText):]
			print("Cipher : ",cipher)
			try:
				decrypted = decrypt(key=password.encode(),source=cipher)
			except Exception as e:
				print("[red]Wrong password![/red]")
				sys.exit(0)

		else:
			decrypted=cipher #if no password, there is no encryption


		header = decrypted.decode()[:len(headerText)] #check header

		if header!=headerText:
			print("[red]Wrong password![/red]")
			sys.exit(0)

		decrypted = decrypted[len(headerText):]
		
		#decrypted_f=decrypted.decode('UTF-8')  #convert byte data type to srting
		#print("[green]Decoded Text: \n[bold]%s[/bold][/green]"%decrypted_f)
		print("[green]Decoded Text: \n[bold]%s[/bold][/green]"%decrypted)
		print()
		wait=input("Press Any Key To Exit\n")





if __name__ == "__main__": #driver code
	os.system('cls' if os.name == 'nt' else 'clear') #clear terminal
	cprint(figlet_format('WELCOME', font='starwars'),'blue', attrs=['bold']) #print welcome message
	print_credits() #print roll table
	print()
	print("Hide texts inside an image and also protect these texts with a password using AES-256.") 
	print()
	
	main() #call main
	