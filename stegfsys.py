import os
from hashlib import sha256

''' Calculate the block id and hash '''
def calcblock(bts,numblocks):
	hsh=sha256(bts)
	block=int.from_bytes(hsh.digest(),byteorder='little',
	signed=False)%numblocks	
	return block, bytes(hsh.hexdigest(),"utf-8")

def encryptdata(value,pwd,blocksize):
	''' SHA256 hash of the password will always be 32 bytes '''
	pwsh=sha256(bytes(pwd,"utf-8")).digest()
	if(len(value)<blocksize):
		''' If too short pad with spaces '''
		val=value.decode("utf-8").ljust(blocksize)
		value=bytes(val,"utf-8")
	return bytes(a ^ b for a, b in zip(value, pwsh))

def decryptdata(value,pwd,blocksize):
	''' SHA256 hash of the password will always be 32 bytes '''
	pwsh=sha256(bytes(pwd,"utf-8")).digest()
	if(len(value)<blocksize):
		''' If too short pad with spaces '''
		val=value.decode("utf-8").ljust(blocksize)
		value=bytes(val,"utf-8")
	try:
		val=bytes(a ^ b for a, b in zip(value, pwsh)).decode("utf-8")
	except:
		val="End of message"	
	return val

def writefsys(fsys,fname,pwd,blocksize,numblocks):
	''' Calculate the first block as the hash of filename+passphrase '''
	block, hshval=calcblock(bytes(pwd+fname,'utf-8'),numblocks)
	outf=open(fsys,"r+b")
	with open(fname, "rb") as inf:
		while True:
			value = inf.read(blocksize)
			if value == b'':
				break # end of file

			#print("Writing to block "+str(block))
			#print(value.decode("utf-8"))
			byts=encryptdata(value,pwd,blocksize)
			outf.seek(block*blocksize)
			outf.write(byts)
			''' the next block is based on hash of this block's hash '''
			block, hshval=calcblock(hshval,numblocks)
			
	''' This is just a bespoke end of file marker '''
	value=bytes("End of message".ljust(blocksize),"utf-8")
	#print("Writing to block "+str(block))
	#print(value.decode("utf-8"))
	byts=encryptdata(value,pwd,blocksize)
	outf.write(byts)
			
	inf.close()
	outf.close()

def readfsys(fsys,fname,pwd,blocksize,numblocks):
	value=""
	rc=""
	''' Calculate the first block as the hash of filename+passphrase '''
	block, hshval=calcblock(bytes(pwd+fname,'utf-8'),numblocks)
	with open(fsys, "rb") as inf:
		while True:
			#print("Reading from block "+str(block))
			inf.seek(block*blocksize)
			binarydata=inf.read(blocksize)
			value=decryptdata(binarydata,pwd,blocksize)
			if value.startswith("End of message"):
				break
			rc+=value
			''' the next block is based on hash of this block's hash '''
			block, hshval=calcblock(hshval,numblocks)

	inf.close()
	return rc

''' Entry point to program '''
if __name__ == '__main__':
	''' The file which contains the file system '''
	fsys="/media/presens/C505-CD1F/bigfile"

	''' A file with the message that must remain secret '''
	fname="./secretmessage.txt"
	
	''' A secret passphrase '''
	pwd="To Heloise"
	
	''' The block size we're using (bytes) '''
	bsz=32
	
	''' Size of the fsys file '''
	fsz=os.path.getsize(fsys)
	
	''' number of blocks in the file system '''
	blknum=int(fsz/bsz)-1

	''' Write the file contents to the file system '''
	writefsys(fsys,fname,pwd,bsz,blknum)
	
	''' Read it back '''
	msg=readfsys(fsys,fname,pwd,bsz,blknum)

	''' Display the message '''	
	print(msg)
