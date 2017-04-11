import binascii
import struct
import datetime
import hashlib
import base58
import sys
import array
import traceback

def log(string):
	print string

def startsWithOpNCode(pub):
	intValue = int(pub[0:2], 16)
	if intValue >= 1 and intValue <= 75:
		return True
	return False

def publicKeyDecode(pub):
	if pub.lower().startswith('76a914'):
		pub = pub[6:-4]
		result = (b'\x00') + binascii.unhexlify(pub)
		h5 = hashlib.sha256(result)
		h6 = hashlib.sha256(h5.digest())
		result += h6.digest()[:4]
		return base58.b58encode(result)
	elif pub.lower().startswith('a9'):
		return ""
	elif startsWithOpNCode(pub):
		pub = pub[2:-2]
		h3 = hashlib.sha256(binascii.unhexlify(pub))
		h4 = hashlib.new('ripemd160', h3.digest())
		result = (b'\x00') + h4.digest()
		h5 = hashlib.sha256(result)
		h6 = hashlib.sha256(h5.digest())
		result += h6.digest()[:4]
		return base58.b58encode(result)
	return ""

def stringLittleEndianToBigEndian(string):
	string = binascii.hexlify(string)
	n = len(string) / 2
	fmt = '%dh' % n
	return struct.pack(fmt, *reversed(struct.unpack(fmt, string)))

def readShortLittleEndian(blockFile):
	return struct.pack(">H", struct.unpack("<H", blockFile.read(2))[0])

def readLongLittleEndian(blockFile):
	return struct.pack(">Q", struct.unpack("<Q", blockFile.read(8))[0])

def readIntLittleEndian(blockFile):
	return struct.pack(">I", struct.unpack("<I", blockFile.read(4))[0])

def hexToInt(value):
	return int(binascii.hexlify(value), 16)

def hexToStr(value):
	return binascii.hexlify(value)

def readVarInt(blockFile):
	varInt = ord(blockFile.read(1))
	returnInt = 0
	if varInt < 0xfd:
		return varInt
	if varInt == 0xfd:
		returnInt = readShortLittleEndian(blockFile)
	if varInt == 0xfe:
		returnInt = readIntLittleEndian(blockFile)
	if varInt == 0xff:
		returnInt = readLongLittleEndian(blockFile)
	return int(binascii.hexlify(returnInt), 16)

def readInput(blockFile):
	previousHash = binascii.hexlify(blockFile.read(32)[::-1])
	outId = binascii.hexlify(readIntLittleEndian(blockFile))
	scriptLength = readVarInt(blockFile)
	scriptSignatureRaw = hexToStr(blockFile.read(scriptLength))
	scriptSignature = scriptSignatureRaw
	seqNo = binascii.hexlify(readIntLittleEndian(blockFile))

	log("\n" + "Input")
	log("-" * 20)
	log("> Previous Hash: " + previousHash)
	log("> Out ID: " + outId)
	log("> Script length: " + str(scriptLength))
	log("> Script Signature (PubKey) Raw: " + scriptSignatureRaw)
	log("> Script Signature (PubKey): " + scriptSignature)
	log("> Seq No: " + seqNo)

def readOutput(blockFile):
	value = hexToInt(readLongLittleEndian(blockFile)) / 100000000.0
	scriptLength = readVarInt(blockFile)
	scriptSignatureRaw = hexToStr(blockFile.read(scriptLength))
	scriptSignature = scriptSignatureRaw
	address = ''
	try:
		address = publicKeyDecode(scriptSignature)
	except Exception, e:
		print e
		address = ''
	log("\n" + "Output")
	log("-" * 20)
	log("> Value: " + str(value))
	log("> Script length: " + str(scriptLength))
	log("> Script Signature (PubKey) Raw: " + scriptSignatureRaw)
	log("> Script Signature (PubKey): " + scriptSignature)
	log("> Address: " + address)

def readTransaction(blockFile):
	beginByte = blockFile.tell()
	inputIds = []
	outputIds = []
	version = hexToInt(readIntLittleEndian(blockFile)) 
	inputCount = readVarInt(blockFile)
	log("\n\n" + "Transaction")
	log("-" * 100)
	log("Version: " + str(version))
	log("\nInput Count: " + str(inputCount))
	for inputIndex in range(0, inputCount):
		inputIds.append(readInput(blockFile))

	outputCount = readVarInt(blockFile)
	log("\nOutput Count: " + str(outputCount))
	for outputIndex in range(0, outputCount):
		outputIds.append(readOutput(blockFile))

	lockTime = hexToInt(readIntLittleEndian(blockFile))
	if lockTime < 500000000:
		log("\nLock Time is Block Height: " + str(lockTime))
	else:
		log("\nLock Time is Timestamp: " + datetime.datetime.fromtimestamp(lockTime).strftime('%d.%m.%Y %H:%M'))

	endByte = blockFile.tell()
	blockFile.seek(beginByte)
	lengthToRead = endByte - beginByte
	dataToHashForTransactionId = blockFile.read(lengthToRead)
	firstHash = hashlib.sha256(dataToHashForTransactionId)
	secondHash = hashlib.sha256(firstHash.digest())
	hashLittleEndian = secondHash.hexdigest()
	hashTransaction = stringLittleEndianToBigEndian(binascii.unhexlify(hashLittleEndian))
	log("\n Hash Transaction: " + hashTransaction)

def readBlock(blockFile):
	magicNumber = binascii.hexlify(blockFile.read(4))
	blockSize = hexToInt(readIntLittleEndian(blockFile))
	version = hexToInt(readIntLittleEndian(blockFile))
	previousHash = binascii.hexlify(blockFile.read(32))
	merkleHash = binascii.hexlify(blockFile.read(32))
	creationTimeTimestamp = hexToInt(readIntLittleEndian(blockFile))
	creationTime = datetime.datetime.fromtimestamp(creationTimeTimestamp).strftime('%d.%m.%Y %H:%M')
	bits = hexToInt(readIntLittleEndian(blockFile))
	nonce = hexToInt(readIntLittleEndian(blockFile))
	countOfTransactions = readVarInt(blockFile)
	log("Magic Number: " + magicNumber)
	log("Blocksize: " + str(blockSize))
	log("Version: " + str(version))
	log("Previous Hash: " + previousHash)
	log("Merkle Hash: " + merkleHash)
	log("Time: " + creationTime)
	log("Bits: " + str(bits))
	log("Nonce: " + str(nonce))
	log("Count of Transactions: " + str(countOfTransactions))
			
	for transactionIndex in range(0, countOfTransactions):
		readTransaction(blockFile)

def main():
	blockFilename = sys.argv[1]
	with open(blockFilename, "rb") as blockFile:
		try:
			while True:
				sys.stdout.write('.')
				sys.stdout.flush()
				readBlock(blockFile)
		except Exception, e:
			excType, excValue, excTraceback = sys.exc_info()
			traceback.print_exception(excType, excValue, excTraceback, limit = 8, file = sys.stdout)

if __name__ == "__main__":
	main()
