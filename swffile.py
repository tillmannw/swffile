'''
swffile.py - SWF file parser module
(C) 2015 by Tillmann Werner, <tillmann.werner@gmx.de>
'''

__author__ = 'Tillmann Werner'
__version__ =  '0.1.0.0'

import pylzma
import zlib
from struct import *

# AVM2 opcodes
opcodes = {}
opcodes[0x02] = { "name" : "nop", "argtypes" : [] }
opcodes[0x03] = { "name" : "throw", "argtypes" : [] }
opcodes[0x04] = { "name" : "getsuper", "argtypes" : [ "u30" ] }
opcodes[0x07] = { "name" : "dxnslate", "argtypes" : [] }
opcodes[0x08] = { "name" : "kill", "argtypes" : [ "register" ] }
opcodes[0x09] = { "name" : "label", "argtypes" : [] }
opcodes[0x0c] = { "name" : "ifnlt", "argtypes" : [ "offset" ] }
opcodes[0x0d] = { "name" : "ifnle", "argtypes" : [ "offset" ] }
opcodes[0x0e] = { "name" : "ifngt", "argtypes" : [ "offset" ] }
opcodes[0x0f] = { "name" : "ifnge", "argtypes" : [ "offset" ] }
opcodes[0x10] = { "name" : "jump", "argtypes" : [ "offset" ] }
opcodes[0x11] = { "name" : "iftrue", "argtypes" : [ "offset" ] }
opcodes[0x12] = { "name" : "iffalse", "argtypes" : [ "offset" ] }
opcodes[0x13] = { "name" : "ifeq", "argtypes" : [ "offset" ] }
opcodes[0x14] = { "name" : "ifne", "argtypes" : [ "offset" ] }
opcodes[0x15] = { "name" : "iflt", "argtypes" : [ "offset" ] }
opcodes[0x16] = { "name" : "ifle", "argtypes" : [ "offset" ] }
opcodes[0x17] = { "name" : "ifgt", "argtypes" : [ "offset" ] }
opcodes[0x18] = { "name" : "ifge", "argtypes" : [ "offset" ] }
opcodes[0x19] = { "name" : "ifstricteq", "argtypes" : [ "offset" ] }
opcodes[0x1a] = { "name" : "ifstrictne", "argtypes" : [ "offset" ] }
opcodes[0x1b] = { "name" : "lookupswitch", "argtypes" : [ "s24", "u30" ] } # + a varying number of s24's
opcodes[0x1c] = { "name" : "pushwith", "argtypes" : [] }
opcodes[0x1d] = { "name" : "popscope", "argtypes" : [] }
opcodes[0x1e] = { "name" : "nextname", "argtypes" : [] }
opcodes[0x1f] = { "name" : "hasnext", "argtypes" : [] }
opcodes[0x20] = { "name" : "pushnull", "argtypes" : [] }
opcodes[0x21] = { "name" : "pushundefined", "argtypes" : [] }
opcodes[0x23] = { "name" : "nextvalue", "argtypes" : [] }
opcodes[0x24] = { "name" : "pushbyte", "argtypes" : [ "u8" ] }
opcodes[0x25] = { "name" : "pushshort", "argtypes" : [ "u30" ] }
opcodes[0x26] = { "name" : "pushtrue", "argtypes" : [] }
opcodes[0x27] = { "name" : "pushfalse", "argtypes" : [] }
opcodes[0x28] = { "name" : "pushnan", "argtypes" : [] }
opcodes[0x29] = { "name" : "pop", "argtypes" : [] }
opcodes[0x2a] = { "name" : "dup", "argtypes" : [] }
opcodes[0x2b] = { "name" : "swap", "argtypes" : [] }
opcodes[0x2c] = { "name" : "pushstring", "argtypes" : [ "string" ] }
opcodes[0x2d] = { "name" : "pushint", "argtypes" : [ "integer" ] }
opcodes[0x2e] = { "name" : "pushuint", "argtypes" : [ "uinteger" ] }
opcodes[0x2f] = { "name" : "pushdouble", "argtypes" : [ "double" ] }
opcodes[0x30] = { "name" : "pushscope", "argtypes" : [] }
opcodes[0x31] = { "name" : "pushnamespace", "argtypes" : [ "u30" ] }
opcodes[0x32] = { "name" : "hasnext2", "argtypes" : [ "register", "register" ] }
opcodes[0x40] = { "name" : "newfunction", "argtypes" : [ "method" ] }
opcodes[0x41] = { "name" : "call", "argtypes" : [ "u30" ] }
opcodes[0x46] = { "name" : "callproperty", "argtypes" : [ "multiname", "u30" ] }
opcodes[0x47] = { "name" : "returnvoid", "argtypes" : [] }
opcodes[0x48] = { "name" : "returnvalue", "argtypes" : [] }
opcodes[0x42] = { "name" : "construct", "argtypes" : [ "u30" ] }
opcodes[0x49] = { "name" : "constructsuper", "argtypes" : [ "u30" ] }
opcodes[0x4a] = { "name" : "constructprop", "argtypes" : [ "multiname", "u30" ] }
opcodes[0x4c] = { "name" : "callproplex", "argtypes" : [ "multiname", "u30" ] }
opcodes[0x4e] = { "name" : "callsupervoid", "argtypes" : [ "multiname", "u30" ] }
opcodes[0x4f] = { "name" : "callpropvoid", "argtypes" : [ "multiname", "u30" ] }
opcodes[0x53] = { "name" : "applytype", "argtypes" : [ "u30" ] }
opcodes[0x55] = { "name" : "newobject", "argtypes" : [ "u30" ] }
opcodes[0x56] = { "name" : "newarray", "argtypes" : [ "u30" ] }
opcodes[0x57] = { "name" : "newactivation", "argtypes" : [] }
opcodes[0x58] = { "name" : "newclass", "argtypes" : [ "u30" ] }
opcodes[0x59] = { "name" : "getdescendants", "argtypes" : [ "u30" ] }
opcodes[0x5a] = { "name" : "newcatch", "argtypes" : [ "u30" ] }
opcodes[0x5d] = { "name" : "findpropstrict", "argtypes" : [ "multiname" ] }
opcodes[0x5e] = { "name" : "findproperty", "argtypes" : [ "multiname" ] }
opcodes[0x5f] = { "name" : "finddef", "argtypes" : [ "multiname" ] }
opcodes[0x60] = { "name" : "getlex", "argtypes" : [ "multiname" ] }
opcodes[0x61] = { "name" : "setproperty", "argtypes" : [ "multiname" ] }
opcodes[0x62] = { "name" : "getlocal", "argtypes" : [ "register" ] }
opcodes[0x63] = { "name" : "setlocal", "argtypes" : [ "register" ] }
opcodes[0x64] = { "name" : "getglobalscope", "argtypes" : [] }
opcodes[0x65] = { "name" : "getscopeobject", "argtypes" : [ "u8" ] }
opcodes[0x66] = { "name" : "getproperty", "argtypes" : [ "multiname" ] }
opcodes[0x68] = { "name" : "initproperty", "argtypes" : [ "multiname" ] }
opcodes[0x6a] = { "name" : "deleteproperty", "argtypes" : [ "multiname" ] }
opcodes[0x6c] = { "name" : "getslot", "argtypes" : [ "u30" ] }
opcodes[0x6d] = { "name" : "setslot", "argtypes" : [ "u30" ] }
opcodes[0x70] = { "name" : "convert_s", "argtypes" : [] }
opcodes[0x73] = { "name" : "convert_i", "argtypes" : [] }
opcodes[0x74] = { "name" : "convert_u", "argtypes" : [] }
opcodes[0x75] = { "name" : "convert_d", "argtypes" : [] }
opcodes[0x76] = { "name" : "convert_b", "argtypes" : [] }
opcodes[0x77] = { "name" : "convert_o", "argtypes" : [] }
opcodes[0x78] = { "name" : "checkfilter", "argtypes" : [] }
opcodes[0x80] = { "name" : "coerce", "argtypes" : [ "multiname" ] }
opcodes[0x82] = { "name" : "coerce_a", "argtypes" : [] }
opcodes[0x85] = { "name" : "coerce_s", "argtypes" : [] }
opcodes[0x87] = { "name" : "astypelate", "argtypes" : [] }
opcodes[0x90] = { "name" : "negate", "argtypes" : [] }
opcodes[0x91] = { "name" : "increment", "argtypes" : [] }
opcodes[0x92] = { "name" : "inclocal", "argtypes" : [ "u30" ] }
opcodes[0x93] = { "name" : "decrement", "argtypes" : [] }
opcodes[0x94] = { "name" : "declocal", "argtypes" : [ "u30" ] }
opcodes[0x95] = { "name" : "typeof", "argtypes" : [] }
opcodes[0x96] = { "name" : "not", "argtypes" : [] }
opcodes[0x97] = { "name" : "bitnot", "argtypes" : [] }
opcodes[0xa0] = { "name" : "add", "argtypes" : [] }
opcodes[0xa1] = { "name" : "subtract", "argtypes" : [] }
opcodes[0xa2] = { "name" : "multiply", "argtypes" : [] }
opcodes[0xa3] = { "name" : "divide", "argtypes" : [] }
opcodes[0xa4] = { "name" : "modulo", "argtypes" : [] }
opcodes[0xa5] = { "name" : "lshift", "argtypes" : [] }
opcodes[0xa6] = { "name" : "rshift", "argtypes" : [] }
opcodes[0xa7] = { "name" : "urshift", "argtypes" : [] }
opcodes[0xa8] = { "name" : "bitand", "argtypes" : [] }
opcodes[0xa9] = { "name" : "bitor", "argtypes" : [] }
opcodes[0xab] = { "name" : "equals", "argtypes" : [] }
opcodes[0xaa] = { "name" : "bitxor", "argtypes" : [] }
opcodes[0xac] = { "name" : "strictequals", "argtypes" : [] }
opcodes[0xad] = { "name" : "lessthan", "argtypes" : [] }
opcodes[0xae] = { "name" : "lessequals", "argtypes" : [] }
opcodes[0xaf] = { "name" : "greaterthan", "argtypes" : [] }
opcodes[0xb0] = { "name" : "greaterequals", "argtypes" : [] }
opcodes[0xb1] = { "name" : "instanceof", "argtypes" : [] }
opcodes[0xb2] = { "name" : "istype", "argtypes" : [ "multiname" ] }
opcodes[0xb3] = { "name" : "istypelate", "argtypes" : [] }
opcodes[0xb4] = { "name" : "in", "argtypes" : [] }
opcodes[0xc0] = { "name" : "increment_i", "argtypes" : [] }
opcodes[0xc1] = { "name" : "decrement_i", "argtypes" : [] }
opcodes[0xc2] = { "name" : "inclocal_i", "argtypes" : [ "u30" ] }
opcodes[0xc3] = { "name" : "declocal_i", "argtypes" : [ "u30" ] }
opcodes[0xc4] = { "name" : "negate_i", "argtypes" : [] }
opcodes[0xc5] = { "name" : "add_i", "argtypes" : [] }
opcodes[0xc6] = { "name" : "subtract_i", "argtypes" : [] }
opcodes[0xc7] = { "name" : "multiply_i", "argtypes" : [] }
opcodes[0xd0] = { "name" : "getlocal_0", "argtypes" : [] }
opcodes[0xd1] = { "name" : "getlocal_1", "argtypes" : [] }
opcodes[0xd2] = { "name" : "getlocal_2", "argtypes" : [] }
opcodes[0xd3] = { "name" : "getlocal_3", "argtypes" : [] }
opcodes[0xd4] = { "name" : "setlocal_0", "argtypes" : [] }
opcodes[0xd5] = { "name" : "setlocal_1", "argtypes" : [] }
opcodes[0xd6] = { "name" : "setlocal_2", "argtypes" : [] }
opcodes[0xd7] = { "name" : "setlocal_3", "argtypes" : [] }
opcodes[0xf0] = { "name" : "debugline", "argtypes" : [ "u30" ] }
opcodes[0xf1] = { "name" : "debugfile", "argtypes" : [ "string" ] }


class SwfHeader():
	def __init__(self, data):
		self.Signature = data[:3]
		self.Version = ord(data[3])
		self.FileLength, = unpack('<I', data[4:8])

		# frame size: varying, depending on nbits, byte-aligned
		self.FrameSize = lambda:0
		self.FrameSize.Nbits = ord(data[8]) >> 3

		totalbits = 5 + 4 * self.FrameSize.Nbits
		off = (totalbits / 8) + (1 if totalbits % 8 != 0 else 0)
		bitstr = ''.join(['{:08b}'.format(ord(b)) for b in data[8:8+off]])
		
		self.FrameSize.Xmin = int(bitstr[5+(0*self.FrameSize.Nbits):5+(1*self.FrameSize.Nbits)], 2)
		self.FrameSize.Xmax = int(bitstr[5+(1*self.FrameSize.Nbits):5+(2*self.FrameSize.Nbits)], 2)
		self.FrameSize.Ymin = int(bitstr[5+(2*self.FrameSize.Nbits):5+(3*self.FrameSize.Nbits)], 2)
		self.FrameSize.Ymax = int(bitstr[5+(3*self.FrameSize.Nbits):5+(4*self.FrameSize.Nbits)], 2)

		self.MovieWidth = (self.FrameSize.Xmax - self.FrameSize.Xmin) / 20.0
		self.MovieHeight = (self.FrameSize.Ymax - self.FrameSize.Ymin) / 20.0

		self.FrameRate = unpack('<H', data[8+off:8+off+2])[0] / 256.0
		self.FrameCount, = unpack('<H', data[8+off+2:8+off+4])

		self.HeaderSize = 8+off+4


class SwfTag():
	def __init__(self, data):
		recordhdr, = unpack('<H', data[:2])
		self.Type = recordhdr >> 6
		self.Length = recordhdr & 0x3f
		off = 2

		if self.Length == 0x3f:
			self.Length, = unpack('<I', data[2:6])
			off += 4

		self.Data = data[off:off+self.Length]
		self.TotalSize = self.Length + off


class RGB():
	def __init__(self, data):
		self.Red = ord(data[0])
		self.Green = ord(data[1])
		self.Blue = ord(data[2])


class SwfFormatError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)


class Flash():
	def __init__(self, filename=None, data=None, unpack=True):
		if filename == None and data == None:
			return None

		if not filename == None:
			self.__orgdata__ = open(filename, 'rb').read()
		else:
			self.__orgdata__ = data

		if unpack == False:
			self.__data__ = self.__orgdata__
		else:
			self.__data__ = self.uncompress(data=self.__orgdata__)

		self.header = self.parseHeader(self.__data__)

		self.tags = self.parseTagList()

		self.tagParser = {
			0x09 : self.parseSetBackgroundColor,
			0x29 : self.parseProductInfo,
			0x3f : self.parseDebugId,
			0x41 : self.parseScriptLimits,
			0x45 : self.parseFileAttributes,
			0x4C : self.parseSymbolClass,
			0x52 : self.parseDoABC,
		}

		self.DoABC = []

		self.parseTags()


	def parseHeader(self, data):
		return SwfHeader(data)


	def __getS24__(self, data):
		if len(data) == 0: return 0

		b = ByteArray(data)
		return b.readS24()

	def __getU30len__(self, data):
		if len(data) == 0: return 0

		i = 0
		while (ord(data[i]) & 0x80):
			i += 1

		return i + 1 


	def __getU30__(self, data):
		if len(data) == 0: return 0

		b = ByteArray(data)
		return b.readU30()


	def uncompress(self, filename=None, data=None):
		# if data has already been uncompressed, return it
		if hasattr(self, '__data__'):
			return self.__data__

		if filename == None and data == None:
			return None

		if not filename == None:
			self.__data__ = open(filename, 'rb').read()
		else:
			self.__data__ = data

		if self.__data__[:3] == 'FWS':
			self.compressed = False
			return self.__data__
		if self.__data__[:3] == 'ZWS':
			self.compressed = True
			rawdata = pylzma.decompress(self.__data__[12:])
		elif self.__data__[:3] == 'CWS':
			self.compressed = True
			rawdata = zlib.decompress(self.__data__[8:])
		else:
			raise SwfFormatError('Unexpected magic string, not a Flash file.')
			
		
		swfdata = 'FWS' + self.__data__[3] + pack('I', len(rawdata) + 8) + rawdata

		return swfdata


	def getTagListOffset(self):
		return


	def getFirstTagOfType(self, tagtype):
		if self.tags is not None:
			for t in self.tags:
				if t['type'] == tagtype:
					return t['data']

		return None


	def parseTagList(self):
		tagListData = self.__data__[self.header.HeaderSize:]
		off = 0

		tags = []
			
		# process list of tags
		while len(tagListData[off:]) > 0:
			tag = SwfTag(tagListData[off:])
			tags.append(tag)
			off += tag.TotalSize

			# end tag reached?
			if tag.Type == 0: break;

		return tags


	def parseTags(self):
		if self.tags is not None:
			for tag in self.tags:
				if tag.Type not in self.tagParser.keys(): continue
				self.tagParser[tag.Type](tag)


	def getActionConstantPool(self):
		tagData = []

		tagList = self.__data__[self.__tagListOffset__:]

		# walk list of tags
		while len(tagList) > 0:
			recordhdr = unpack('<I', tagList[:4])[0]
			tagList = tagList[4:]

			print "%04d - %d" % (tagtype, taglen)
			if tagtype == 0x88:
				# binaryData tag: skip 2 bytes character ID and 4 reserved bytes
				tagData.append(tagList[:taglen])

			tagList = tagList[taglen:]

		return tagData


	# tag 0x09
	def parseSetBackgroundColor(self, tag):
		self.SetBackgroundColor = lambda:0
		self.SetBackgroundColor.BackgroundColor = RGB(tag.Data)


	# tag 0x29
	def parseProductInfo(self, tag):
		self.ProductInfo = lambda:0
		self.ProductInfo.ProductId, = unpack('<I', tag.Data[:4])
		self.ProductInfo.Edition, = unpack('<I', tag.Data[4:8])
		self.ProductInfo.MajorVersion = ord(tag.Data[8])
		self.ProductInfo.MinorVersion = ord(tag.Data[9])
		self.ProductInfo.BuildLow, = unpack('<I', tag.Data[10:14])
		self.ProductInfo.BuildHigh, = unpack('<I', tag.Data[14:18])
		self.ProductInfo.CompilationDate, = unpack('<Q', tag.Data[18:26])

		from datetime import datetime
		self.ProductInfo.CompilationDateString = datetime.utcfromtimestamp(self.ProductInfo.CompilationDate/1000.0).strftime("%Y-%m-%d %H:%M:%S UTC")

		return	


	# tag 0x3f
	def parseDebugId(self, tag):
		return

	
	# tag 0x41
	def parseScriptLimits(self, tag):
		self.ScriptLimits = lambda:0
		self.ScriptLimits.MaxRecursionDepth, = unpack('<H', tag.Data[0:2])
		self.ScriptLimits.ScriptTimeoutSeconds, = unpack('<H', tag.Data[2:4])


	# tag 0x45
	def parseFileAttributes(self, tag):
		if self.header.Version < 7:
			raise SwfFormatError('FileAttributes tag not supported by this SWF version.')

		if tag.Length != 4 or len(tag.Data) != 4:
			raise SwfFormatError('FileAttributes tag has an invalid size.')

		self.Flags = lambda:0
		self.Flags.Value, = unpack('<I', tag.Data)
		self.Flags.UseDirectBlit = 0 != self.Flags.Value & (1 << 5)
		self.Flags.UseGPU = 0 != self.Flags.Value & (1 << 6)
		self.Flags.HasMetadata = 0 != self.Flags.Value & (1 << 4)
		self.Flags.ActionScript3 = 0 != self.Flags.Value & (1 << 3)
		self.Flags.UseNetwork = 0 != self.Flags.Value & (1 << 0)


	# tag 0c4c
	def parseSymbolClass(self, tag):
		self.SymbolClass = lambda:0
		self.SymbolClass.NumSymbols, = unpack('<H', tag.Data[0:2])
		off = 2

		self.SymbolClass.Tags = []
		self.SymbolClass.Names = []

		for i in range(self.SymbolClass.NumSymbols):
			TagId, = unpack('<H', tag.Data[off:off+2])
			Name = tag.Data[off+2:off+2+tag.Data[off+2:].find('\0')]
			self.SymbolClass.Tags.append(TagId)
			self.SymbolClass.Names.append(Name)
			off += 2 + len(Name) + 1


	# tag 0x52
	def parseDoABC(self, tag):
		if self.header.Version < 9:
			raise SwfFormatError('DoABC tag found in SWF version that does not support it.')

		DoABC = lambda:0
		DoABC.Flags = lambda:0

		DoABC.Flags.Value, = unpack('<I', tag.Data[:4])
		DoABC.Flags.kDoAbcLazyInitializeFlag = 0 != (DoABC.Flags.Value & 1)
		DoABC.Name = tag.Data[4:5+tag.Data[4:].find('\0')]
		DoABC.ABCData = tag.Data[4+len(DoABC.Name):]

		self.DoABC.append(DoABC)

	def __disas_method__(self, abc, method):
		if method.kind == 1:
			Params = ''
			if len(method.paramNames):
				for i in range(len(method.paramNames)):
					if Params != '':
						Params += ", "
					if method.paramNames[i] == '':
						if isinstance(method.paramTypes[i].name, str):
							Params += "param" + str(i+1) + ":" + method.paramTypes[i].name
						elif hasattr(method.paramTypes[i].name, 'name'):
							Params += "param" + str(i+1) + ":" + method.paramTypes[i].name.name
					else:
						if method.paramTypes[i].name != None:
							Params += method.paramNames[i] + ":" + method.paramTypes[i].name

			return self.parseAvm2Data(abc, method.code)
		else:
			# FIXME: add support for other kinds
			return None
			


	def disassembleABC(self, DoABC):
		if not hasattr(DoABC, 'ABCData'):
			raise SwfFormatError('DoABC tag without data.')

		abc = Abc(DoABC.ABCData, DoABC.Name)

		if abc.major != 46 or abc.minor != 16:
			raise SwfFormatError('Unsupported AVM2 version.')

		for c in abc.classes:
			c.disassembly = {}

			c.disassembly['class initializer'] = self.parseAvm2Data(abc, c.init.code)
			c.disassembly['instance initializer'] = self.parseAvm2Data(abc, c.itraits.init.code)

			for name, method in c.itraits.names.iteritems():
				if method.kind == 1:
					c.disassembly[name] = self.__disas_method__(abc, method)

			for name, method in c.names.iteritems():
				if method.kind == 1:
					c.disassembly[name] = self.__disas_method__(abc, method)

		return abc


	def parseAvm2Data(self, abc, code, ignoreUnknown=False):
		disas = {}
		insns = []

		disas['insns'] = insns
		disas['rawdata'] = code

		if code == None: return disas

		off = 0
		while off < len(code):
			try:
				opcode = opcodes[ord(code[off])]['name']
			except KeyError:
				if ignoreUnknown == False:
					raise SwfFormatError('Unsupported opcode: 0x%02x' % ord(code[off]))
				else:
					# ignore unknown bytes
					off += 1
					continue
			else:
				pass
				
			size = 1

			args = []
			argtypes = opcodes[ord(code[off])]['argtypes']

			# 'lookupswitch' is the only variable-length instruction
			if opcode == 'lookupswitch':
				# default offset
				args.append(self.__getS24__(code[off+size:off+size+3]) + off + size + 3)
				size += 3
				
				# number of cases
				args.append(ord(code[off+size]))
				size += 1

				# skip over offsets
				for i in range(0, args[-1]+1):
					args.append(self.__getS24__(code[off+size:off+size+3]) + off + size + 3)
					argtypes.append('offset')
					size += 3
			else:
				for argtype in argtypes:
					if argtype in ['u8']:
						args.append(ord(code[off+size]))
						size += 1

					if argtype in ['offset']:
						args.append(self.__getS24__(code[off+size:off+size+3]) + off + size + 3)
						size += 3
#						arg = hex(arg)[2:]

					if argtype in ['u30', 'register', 'multiname', 'method']:
						args.append(self.__getU30__(code[off+size:]))
						size += self.__getU30len__(code[off+size:])

#					if argtype in ['multiname_u30', 'register_register']:
#						l = self.__getU30len__(code[off+1:])
#						size +=l
#						size += self.__getU30len__(code[off+1+l:])
#						# FIXME: resolve these
#						args.append(argtype)

					if argtype in ['integer']:
						i = self.__getU30__(code[off+size:])
						args.append(abc.ints[i])
						size += self.__getU30len__(code[off+size:])

					if argtype in ['uinteger']:
						i = self.__getU30__(code[off+size:])
						args.append(abc.uints[i])
						size += self.__getU30len__(code[off+size:])

					if argtype in ['double']:
						i = self.__getU30__(code[off+size:])
						args.append(abc.doubles[i])
						size += self.__getU30len__(code[off+size:])

					if argtype in ['string']:
						i = self.__getU30__(code[off+size:])
						args.append('"' + abc.strings[i] + '"')
						size += self.__getU30len__(code[off+size:])

			hexcode = ''.join("{:02x} ".format(ord(b)) for b in code[off:off+size])

			insn = {}
			insn['args'] = args
			insn['argtypes'] = argtypes
			insn['hexcode'] = hexcode
			insn['offset'] = int(off)
			insn['opcode'] = opcode
			insn['rawbytes'] = code[int(off):int(off)+size]
			insn['size'] = size

			insns.append(insn)

			off += size

		return disas


''' start of 3rd-party code'''

# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is [Open Source Virtual Machine].
#
# The Initial Developer of the Original Code is
# Adobe System Incorporated.
# Portions created by the Initial Developer are Copyright (C) 2007
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Adobe AS3 Team
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

from struct import *
from math import floor

NEED_ARGUMENTS		= 0x01
NEED_ACTIVATION		= 0x02
NEED_REST			= 0x04
HAS_OPTIONAL		= 0x08
IGNORE_REST			= 0x10
NATIVE				= 0x20
HAS_ParamNames		= 0x80

CONSTANT_Utf8               = 0x01
CONSTANT_Int	            = 0x03
CONSTANT_UInt               = 0x04
CONSTANT_PrivateNs	        = 0x05
CONSTANT_Double             = 0x06
CONSTANT_Qname              = 0x07
CONSTANT_Namespace	        = 0x08
CONSTANT_Multiname          = 0x09
CONSTANT_False              = 0x0A
CONSTANT_True               = 0x0B
CONSTANT_Null               = 0x0C
CONSTANT_QnameA             = 0x0D
CONSTANT_MultinameA         = 0x0E
CONSTANT_RTQname	        = 0x0F
CONSTANT_RTQnameA	        = 0x10
CONSTANT_RTQnameL	        = 0x11
CONSTANT_RTQnameLA	        = 0x12
CONSTANT_NameL				= 0x13
CONSTANT_NameLA				= 0x14
CONSTANT_NamespaceSet       = 0x15
CONSTANT_PackageNs			= 0x16
CONSTANT_PackageInternalNs  = 0x17
CONSTANT_ProtectedNs		= 0x18
CONSTANT_ExplicitNamespace  = 0x19
CONSTANT_StaticProtectedNs  = 0x1A
CONSTANT_MultinameL         = 0x1B
CONSTANT_MultinameLA        = 0x1C
CONSTANT_TypeName	        = 0x1D

TRAIT_Slot			= 0x00
TRAIT_Method		= 0x01
TRAIT_Getter		= 0x02
TRAIT_Setter		= 0x03
TRAIT_Class			= 0x04
TRAIT_Const			= 0x06
TRAIT_mask			= 15

ATTR_final			= 0x10
ATTR_override       = 0x20
ATTR_metadata       = 0x40

CTYPE_VOID			= 0
CTYPE_ATOM			= 1
CTYPE_BOOLEAN		= 2
CTYPE_INT			= 3
CTYPE_UINT			= 4
CTYPE_DOUBLE		= 5
CTYPE_STRING		= 6
CTYPE_NAMESPACE		= 7
CTYPE_OBJECT		= 8

MPL_HEADER = "/* ***** BEGIN LICENSE BLOCK *****\n" \
            " * Version: MPL 1.1/GPL 2.0/LGPL 2.1\n" \
            " *\n" \
            " * The contents of this file are subject to the Mozilla Public License Version\n" \
            " * 1.1 (the \"License\"); you may not use this file except in compliance with\n" \
            " * the License. You may obtain a copy of the License at\n" \
            " * http://www.mozilla.org/MPL/\n" \
            " *\n" \
            " * Software distributed under the License is distributed on an \"AS IS\" basis,\n" \
            " * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License\n" \
            " * for the specific language governing rights and limitations under the\n" \
            " * License.\n" \
            " *\n" \
            " * The Original Code is [Open Source Virtual Machine].\n" \
            " *\n" \
            " * The Initial Developer of the Original Code is\n" \
            " * Adobe System Incorporated.\n" \
            " * Portions created by the Initial Developer are Copyright (C) 2008\n" \
            " * the Initial Developer. All Rights Reserved.\n" \
            " *\n" \
            " * Contributor(s):\n" \
            " *   Adobe AS3 Team\n" \
            " *\n" \
            " * Alternatively, the contents of this file may be used under the terms of\n" \
            " * either the GNU General Public License Version 2 or later (the \"GPL\"), or\n" \
            " * the GNU Lesser General Public License Version 2.1 or later (the \"LGPL\"),\n" \
            " * in which case the provisions of the GPL or the LGPL are applicable instead\n" \
            " * of those above. If you wish to allow use of your version of this file only\n" \
            " * under the terms of either the GPL or the LGPL, and not to allow others to\n" \
            " * use your version of this file under the terms of the MPL, indicate your\n" \
            " * decision by deleting the provisions above and replace them with the notice\n" \
            " * and other provisions required by the GPL or the LGPL. If you do not delete\n" \
            " * the provisions above, a recipient may use your version of this file under\n" \
            " * the terms of any one of the MPL, the GPL or the LGPL.\n" \
            " *\n" \
            " * ***** END LICENSE BLOCK ***** */" 

# Python 2.5 and earlier didn't reliably handle float("nan") and friends uniformly
# across all platforms. This is a workaround that appears to be more reliable.
# if/when we require Python 2.6 or later we can use a less hack-prone approach
kPosInf = 1e300000
kNegInf = -1e300000
kNaN = kPosInf / kPosInf

def is_nan(val):
	strValLower = str(val).lower()
	return strValLower == "nan"

def is_pos_inf(val):
	# [-]1.#INF on Windows in Python 2.5.2!
	strValLower = str(val).lower()
	return strValLower.endswith("inf") and not strValLower.startswith("-")

def is_neg_inf(val):
	# [-]1.#INF on Windows in Python 2.5.2!
	strValLower = str(val).lower()
	return strValLower.endswith("inf") and strValLower.startswith("-")

class Error(Exception):
	nm = ""
	def __init__(self, n):
		self.nm = n
	def __str__(self):
		return self.nm

TMAP = {
	CTYPE_OBJECT:		("o", "AvmObject"),
	CTYPE_ATOM:			("a", "AvmBox"),
	CTYPE_VOID:			("v", "void"),
	CTYPE_BOOLEAN:		("b", "AvmBool32"),
	CTYPE_INT:			("i", "int32_t"),
	CTYPE_UINT:			("u", "uint32_t"),
	CTYPE_DOUBLE:		("d", "double"),
	CTYPE_STRING:		("s", "AvmString"),
	CTYPE_NAMESPACE:	("n", "AvmNamespace")
};

def uint(i):
	return int(i) & 0xffffffff

def sigchar_from_enum(ct, allowObject):
	if ct == CTYPE_OBJECT and not allowObject:
		ct = CTYPE_ATOM
	return TMAP[ct][0]

def sigchar_from_traits(t, allowObject):
	return sigchar_from_enum(t.ctype, allowObject)

def ctype_from_enum(ct, allowObject):
	if ct == CTYPE_OBJECT and not allowObject:
		ct = CTYPE_ATOM
	return TMAP[ct][1]

def ctype_from_traits(t, allowObject):
	return ctype_from_enum(t.ctype, allowObject)

def to_cname(nm):
	nm = str(nm)
	nm = nm.replace("+", "_");
	nm = nm.replace("-", "_");
	nm = nm.replace("?", "_");
	nm = nm.replace("!", "_");
	nm = nm.replace("<", "_");
	nm = nm.replace(">", "_");
	nm = nm.replace("=", "_");
	nm = nm.replace("(", "_");
	nm = nm.replace(")", "_");
	nm = nm.replace("\"", "_");
	nm = nm.replace("'", "_");
	nm = nm.replace("*", "_");
	nm = nm.replace(" ", "_");
	nm = nm.replace(".", "_");
	nm = nm.replace("$", "_");
	nm = nm.replace("::", "_");
	nm = nm.replace(":", "_");
	nm = nm.replace("/", "_");
	return nm

def ns_prefix(ns, iscls):
	if not ns.isPublic() and not ns.isInternal():
		if ns.isPrivate() and not iscls:
			return "private_";
		if ns.isProtected():
			return "protected_";
		if ns.srcname != None:
			return to_cname(str(ns.srcname)) + "_"
	p = to_cname(ns.uri);
	if len(p) > 0:
		p += "_"
	return p

class Namespace:
	uri = ""
	kind = 0
	srcname = None
	def __init__(self, uri, kind):
		self.uri = uri
		self.kind = kind
	def __str__(self):
		return self.uri
	def isPublic(self):
		return self.kind in [CONSTANT_Namespace, CONSTANT_PackageNs] and self.uri == ""
	def isInternal(self):
		return self.kind in [CONSTANT_PackageInternalNs]
	def isPrivate(self):
		return self.kind in [CONSTANT_PrivateNs]
	def isProtected(self):
		return self.kind in [CONSTANT_ProtectedNs, CONSTANT_StaticProtectedNs]

class QName:
	ns = None
	name = ""
	def __init__(self, ns, name):
		self.ns = ns
		self.name = name
	def __str__(self):
		if str(self.ns) == "":
			return self.name
		if self.ns == None:
			return "*::" + self.name
		return str(self.ns) + "::" + self.name

class Multiname:
	nsset = None
	name = ""
	def __init__(self, nsset, name):
		self.nsset = nsset
		self.name = name
	def __str__(self):
		nsStrings = map(lambda ns: u'"' + ns.decode("utf8") + u'"', self.nsset)
		stringForNSSet = u'[' + u', '.join(nsStrings) + u']'
		return stringForNSSet + u'::' + unicode(self.name.decode("utf8"))

def stripVersion(ns):
	# version markers are 3 bytes beginning with 0xE0 or greater
	if len(ns.uri) < 3:
	    return ns
	if ns.uri[len(ns.uri)-3] > chr(0xE0):
	    ns.uri = ns.uri[0:len(ns.uri)-3]
	return ns

def isVersionedNamespace(ns):
	# version markers are 3 bytes beginning with 0xE0 or greater
	if len(ns.uri) < 3:
	    return False
	if ns.uri[len(ns.uri)-3] > chr(0xE0):
	    ns.uri = ns.uri[0:len(ns.uri)-3]
	    return True
	return False

def isVersionedName(name):
	if isinstance(name, QName):
            return isVersionedNamespace(name.ns)
	for ns in name.nsset:
            if isVersionedNamespace(ns):
                return True
        return False

class TypeName:
	name = ""
	types = None
	def __init__(self, name, types):
		self.name = name
		self.types = types
	def __str__(self):
		# @todo horrible special-casing, improve someday
		s = str(self.name)
		t = str(self.types[0])
		if t == "int":
			s += "$int"
		elif t == "uint":
			s += "$uint"
		elif t == "Number":
			s += "$double"
		else:
			s += "$object"
		return s

class MetaData:
	name = ""
	attrs = {}
	def __init__(self, name):
		self.name = name
		self.attrs = {}

class MemberInfo:
	id = -1
	kind = -1
	name = ""
	metadata = None

class MethodInfo(MemberInfo):
	flags = 0
	debugName = ""
	paramTypes = None
	paramNames = None
	optional_count = 0
	optionalValues = None
	returnType = None
	local_count = 0
	max_scope = 0
	max_stack = 0
	code_length = 0
	code = None
	activation = None
	native_id_name = None
	native_method_name = None
	final = False
	override = False
	receiver = None
	unbox_this = -1 # -1 == undetermined, 0 = no, 1 = yes

	def isNative(self):
		return (self.flags & NATIVE) != 0

	def needRest(self):
		return (self.flags & NEED_REST) != 0

	def hasOptional(self):
		return (self.flags & HAS_OPTIONAL) != 0

	def assign_names(self, traits, prefix):
		self.receiver = traits
		
		if not self.isNative():
			return
		
		if self == traits.init:
			raise Error("ctors cannot be native")

		assert(isinstance(self.name, QName))
		self.native_id_name = prefix + ns_prefix(self.name.ns, False) + self.name.name
		self.native_method_name = self.name.name
		
		if self.kind == TRAIT_Getter:
			self.native_id_name += "_get"
			self.native_method_name = "get_" + self.native_method_name
		elif self.kind == TRAIT_Setter:
			self.native_id_name += "_set"		
			self.native_method_name = "set_" + self.native_method_name

		if self.name.ns.srcname != None:
			self.native_method_name = str(self.name.ns.srcname) + "_" + self.native_method_name

		# if we are an override, prepend the classname to the C method name.
		# (native method implementations must not be virtual, and some compilers
		# will be unhappy if a subclass overrides a method with the same name and signature
		# without it being virtual.) Note that we really only need to do this if the ancestor
		# implementation is native, rather than pure AS3, but we currently do it regardless.
		if self.override:
			self.native_method_name = traits.name.name + "_" + self.native_method_name

		self.native_method_name = to_cname(self.native_method_name)
					
class SlotInfo(MemberInfo):
	type = ""
	value = ""
	fileOffset = -1

class NativeInfo:
	class_name = None
	instance_name = None
	gen_method_map = False
	method_map_name = None
	constSetters = False
	
	def set_class(self, name):
		if self.class_name != None:
			raise Error("native(cls) may not be specified multiple times for the same class: %s %s" % (self.class_name, name))
		self.class_name = name

	def set_instance(self, name):
		if self.instance_name != None:
			raise Error("native(instance) may not be specified multiple times for the same class: %s %s" % (self.instance_name, name))
		self.instance_name = name
		
	def validate(self):
		if self.gen_method_map and self.class_name == None and self.instance_name == None:
			raise Error("cannot specify native(methods) without native(cls)")
		if self.class_name != None or self.instance_name != None:
			# if nothing specified, use ClassClosure/ScriptObject.
			if self.class_name == None:
				self.class_name = "ClassClosure"
			if self.instance_name == None:
				self.instance_name = "ScriptObject"
			

BMAP = {
	"Object": CTYPE_ATOM, # yes, items of exactly class "Object" are stored as Atom; subclasses are stored as pointer-to-Object
	"null": CTYPE_ATOM,
	"*": CTYPE_ATOM,
	"void": CTYPE_VOID,
	"int": CTYPE_INT,
	"uint": CTYPE_UINT,
	"Number": CTYPE_DOUBLE,
	"Boolean": CTYPE_BOOLEAN,
	"String": CTYPE_STRING,
	"Namespace": CTYPE_NAMESPACE
};

class Traits:
	name = ""
	qname = None
	init = None
	itraits = None
	base = None
	flags = 0
	protectedNs = 0
	is_interface = False
	interfaces = None
	names = None
	slots = None
	tmethods = None
	members = None
	class_id = -1
	ctype = CTYPE_OBJECT
	metadata = None
	ni = None
	niname = None
	nextSlotId = 0
	def __init__(self, name):
		self.names = {}
		self.slots = []
		self.tmethods = []
		self.name = name
		if BMAP.has_key(str(name)):
			self.ctype = BMAP[str(name)]
	def __str__(self):
		return str(self.name)

NULL = Traits("*")
UNDEFINED = Traits("void")

class ByteArray:
	data = None
	pos = 0
	def __init__(self, data):
		self.data = data
		self.pos = 0
		
	def readU8(self):
		r = unpack_from("B", self.data, self.pos)[0]
		self.pos += 1
		assert(r >= 0 and r <= 255)
		return r

	def readU16(self):
		r = unpack_from("<h", self.data, self.pos)[0]
		self.pos += 2
		assert(r >= 0 and r <= 65535)
		return r

	def readDouble(self):
		r = unpack_from("<d", self.data, self.pos)[0]
		self.pos += 8
		return r

	def readBytes(self, lenbytes):
		r = self.data[self.pos:self.pos+lenbytes]
		self.pos += lenbytes
		return r

	def readUTF8(self):
		lenbytes = self.readU30()
		return self.readBytes(lenbytes)

	def readS24(self):
		d = self.readBytes(3)
		return unpack_from('<i', d + ('\xff' if (ord(d[2]) & 0x80) else '\x00' ))[0]

	def readU30(self):
		result = self.readU8()
		if not result & 0x00000080:
			return result
		result = (result & 0x0000007f) | (self.readU8() << 7)
		if not result & 0x00004000:
			return result
		result = (result & 0x00003fff) | (self.readU8() << 14)
		if not result & 0x00200000:
			return result
		result = (result & 0x001fffff) | (self.readU8() << 21)
		if not result & 0x10000000:
			return result
		result = (result & 0x0fffffff) | (self.readU8() << 28)
		return result


class Abc():
	data = None
	major = 0
	minor = 0
	ints = None
	uints = None
	doubles = None
	strings = None
	namespaces = None
	nssets = None
	names = None
	defaults = None
	methods = None
	instances = None
	metadata = None
	classes = None
	scripts = None
	scriptName = ""
	publicNs = Namespace("", CONSTANT_Namespace)
	anyNs = Namespace("*", CONSTANT_Namespace)

	magic = 0
	
	qnameToName = {}
	nameToQName = {}
		
	def __init__(self, data, scriptName):
		self.scriptName = scriptName
		self.data = ByteArray(data)

		if self.data.readU16() != 16 or self.data.readU16() != 46:
			raise Error("Bad Abc Version")

		self.major = 46
		self.minor = 16

		self.parseCpool()
		
		self.defaults = [ (None, 0) ] * 32
		self.defaults[CONSTANT_Utf8] = (self.strings, CTYPE_STRING)
		self.defaults[CONSTANT_Int] = (self.ints, CTYPE_INT)
		self.defaults[CONSTANT_UInt] = (self.uints, CTYPE_UINT)
		self.defaults[CONSTANT_Double] = (self.doubles, CTYPE_DOUBLE)
		self.defaults[CONSTANT_False] = ({ CONSTANT_False: False }, CTYPE_BOOLEAN)
		self.defaults[CONSTANT_True] = ({ CONSTANT_True: True }, CTYPE_BOOLEAN)
		self.defaults[CONSTANT_Namespace] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_PrivateNs] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_PackageNs] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_PackageInternalNs] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_ProtectedNs] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_StaticProtectedNs] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_ExplicitNamespace] = (self.namespaces, CTYPE_NAMESPACE)
		self.defaults[CONSTANT_Null] = ({ CONSTANT_Null: None }, CTYPE_ATOM)	
		
		self.parseMethodInfos()
		self.parseMetadataInfos()
		self.parseInstanceInfos()
		self.parseClassInfos()
		self.parseScriptInfos()
		self.parseMethodBodies()

		for i in range(0, len(self.classes)):
			c = self.classes[i]
			assert(isinstance(c.name, QName))
			prefix = ns_prefix(c.name.ns, True) + to_cname(c.name.name)
			c.class_id = i
			c.ni = self.find_class_nativeinfo(c)
			c.niname = c.ni.class_name
			self.assign_names(c, prefix)
			if c.itraits:
				c.itraits.ni = c.ni
				c.itraits.niname = c.ni.instance_name
				self.assign_names(c.itraits, prefix)
		
		for i in range(0, len(self.scripts)):
			script = self.scripts[i]
			if script != None:
				for j in range(0, len(script.tmethods)):
					m = script.tmethods[j]
					if m.metadata != None:
						for md in m.metadata:
							if md.name == "native":
								if md.attrs.has_key("script"):
									raise Error("native(script) is no longer supported; please use a native(\"function-name\") instead: " + str(m.name))
								if len(md.attrs) != 1 or not md.attrs.has_key(""):
									raise Error("native(\"function-name\") is the only form supported here" + str(m.name))
								if not m.isNative():
									raise Error("native(\"function-name\") can only be used on native functions" + str(m.name))
								m.receiver = None
								m.native_method_name = md.attrs[""]     # override 
								m.native_id_name = "native_script_function_" + ns_prefix(m.name.ns, False) + m.name.name
								#m.native_id_name = "native_script_function_" + to_cname(m.native_method_name)
								m.gen_method_map = True


	def assign_names(self, traits, prefix):
		if traits.init != None:
			traits.init.assign_names(traits, prefix)
		for j in range(0, len(traits.tmethods)):
			traits.tmethods[j].assign_names(traits, prefix)

	def default_ctype_and_value(self,d):
		kind, index = d
		deftable = self.defaults[kind]
		if deftable[0] != None:
			val = str(deftable[0][index])
			ct = deftable[1]
		else:
			assert(kind == 0 and index == 0)
			val = "kAvmThunkUndefined"
			ct = CTYPE_ATOM # yes, not void
		rawval = val
		if ct == CTYPE_DOUBLE:
			# Python apparently doesn't have isNaN, isInf
			if is_nan(val):
				val = "kAvmThunkNaN"
			elif is_neg_inf(val):
				val = "kAvmThunkNegInfinity"
			elif is_pos_inf(val):
				val = "kAvmThunkInfinity"
			elif float(val) >= -2147483648.0 and float(val) <= 2147483647.0 and float(val) == floor(float(val)):
				ct = CTYPE_INT
				val = "%.0f" % float(val)
			elif float(val) >= 0.0 and float(val) <= 4294967295.0 and float(val) == floor(float(val)):
				ct = CTYPE_UINT
				val = "%.0fU" % float(val)
		elif ct == CTYPE_STRING:
			for i in range(0, len(self.strings)):
				if (self.strings[i] == str(val)):
					val = "AvmThunkConstant_AvmString("+str(i)+")/* \""+self.strings[i]+"\" */";
					break
		elif ct == CTYPE_BOOLEAN:
			assert(str(val) == "False" or str(val) == "True")
			if str(val) == "False":
				val = "false"
			else:
				val = "true"
		if str(val) == "None":
			val = "kAvmThunkNull"
		return ct,val,rawval
	
	def parseCpool(self):
		
		n = self.data.readU30()
		self.ints = [0] * max(1,n)
		for i in range(1, n):
			ii = self.data.readU30()
			if float(ii) > 2147483647.0:
				ii = int(ii - 4294967296.0)
			assert(int(ii) >= -2147483648 and int(ii) <= 2147483647)
			self.ints[i] = int(ii)
			
		n = self.data.readU30()
		self.uints = [0] * max(1,n)
		for i in range(1, n):
			self.uints[i] = uint(self.data.readU30())
			
		n = self.data.readU30()
		self.doubles = [ kNaN ] * max(1,n)
		for i in range(1, n):
			self.doubles[i] = self.data.readDouble()

		n = self.data.readU30()
		self.strings = [""] * max(1,n)
		for i in range(1, n):
			self.strings[i] = self.data.readUTF8()

		n = self.data.readU30()
		self.namespaces = [self.anyNs] * max(1,n)
		for i in range(1, n):
			nskind = self.data.readU8()
			if nskind in [CONSTANT_Namespace, 
							CONSTANT_PackageNs, 
							CONSTANT_PackageInternalNs,
							CONSTANT_ProtectedNs,
							CONSTANT_ExplicitNamespace,
							CONSTANT_StaticProtectedNs]:
				self.namespaces[i] = Namespace(self.strings[self.data.readU30()], nskind)
			elif nskind in [CONSTANT_PrivateNs]:
				self.data.readU30() # skip
				self.namespaces[i] = Namespace("private", CONSTANT_PrivateNs)

		n = self.data.readU30()
		self.nssets = [ None ] * max(1,n)
		for i in range(1, n):
			count = self.data.readU30()
			self.nssets[i] = []
			for j in range(0, count):
				self.nssets[i].append(self.namespaces[self.data.readU30()])

		n = self.data.readU30()
		self.names = [ None ] * max(1,n)
		for i in range(1, n):
			namekind = self.data.readU8()
			if namekind in [CONSTANT_Qname, CONSTANT_QnameA]:
				self.names[i] = QName(self.namespaces[self.data.readU30()], self.strings[self.data.readU30()])

			elif namekind in [CONSTANT_RTQname, CONSTANT_RTQnameA]:
				self.names[i] = QName(self.anyNs, self.strings[self.data.readU30()])

			elif namekind in [CONSTANT_RTQnameL, CONSTANT_RTQnameLA]:
				self.names[i] = None

			elif namekind in [CONSTANT_NameL, CONSTANT_NameLA]:
				self.names[i] = QName(Namespace(""), None)

			elif namekind in [CONSTANT_Multiname, CONSTANT_MultinameA]:
				name = self.strings[self.data.readU30()]
				nsset = self.nssets[self.data.readU30()]
				self.names[i] = Multiname(nsset, name)

			elif namekind in [CONSTANT_MultinameL, CONSTANT_MultinameLA]:
				nsset = self.nssets[self.data.readU30()]
				self.names[i] = Multiname(nsset, None)

			elif namekind in [CONSTANT_TypeName]:
				name = self.names[self.data.readU30()];
				count = self.data.readU30();
				types = []
				for j in range(0, count):
					types.append(self.names[self.data.readU30()]);
				self.names[i] = TypeName(name, types);
			else:
				raise Error("Bad Kind")

	def parseMethodInfos(self):
		self.names[0] = QName(self.publicNs,"*")
		method_count = self.data.readU30()
		self.methods = [ None ] * method_count
		for i in range(0, method_count):
			m = MethodInfo()
			self.methods[i] = m
			param_count = self.data.readU30()
			m.returnType = self.names[self.data.readU30()]
			m.paramTypes = [ None ] * param_count
			m.paramNames = [ "" ] * param_count
			m.optional_count = 0
			for j in range(0, param_count):
				m.paramTypes[j] = self.names[self.data.readU30()]
			m.debugName = self.strings[self.data.readU30()]
			m.flags = self.data.readU8()
			if m.hasOptional():
				m.optional_count = self.data.readU30();
				m.optionalValues = [ (-1, -1) ] * param_count
				for k in range(param_count-m.optional_count, param_count):
					index = self.data.readU30()
					kind = self.data.readU8()
					m.optionalValues[k] = (kind, index)
			if (m.flags & HAS_ParamNames) != 0:
				for j in range(0, param_count):
					m.paramNames[j] = self.strings[self.data.readU30()]

	def parseMetadataInfos(self):
		count = self.data.readU30()
		self.metadata = [ None ] * count
		for i in range (0, count):
			mname = self.strings[self.data.readU30()]
			m = MetaData(mname)
			self.metadata[i] = m
			values_count = self.data.readU30()
			names = [ None ] * values_count
			for q in range(0, values_count):
				names[q] = self.strings[self.data.readU30()]
			for q in range(0, values_count):
				m.attrs[names[q]] = self.strings[self.data.readU30()] 

	def parseInstanceInfos(self):
		count = self.data.readU30()
		self.instances = [ None ] * count
		instancesDict = {}
		for i in range (0, count):
			tname = self.names[self.data.readU30()]
			t = Traits(tname)
			self.instances[i] = t
			instancesDict[id(tname)] = t
			t.base = self.names[self.data.readU30()]
			t.flags = self.data.readU8()
			if (t.flags & 4) != 0:
				t.is_interface = True
			if (t.flags & 8) != 0:
				t.protectedNs = self.namespaces[self.data.readU30()]
			interface_count = self.data.readU30()
			t.interfaces = [None] * interface_count
			for j in range(0, interface_count):
				t.interfaces[j] = self.names[self.data.readU30()]
			methid = self.data.readU30()
			t.init = self.methods[methid]
			t.init.name = t.name
			t.init.kind = TRAIT_Method
			t.init.id = methid
			self.parseTraits(t, instancesDict.get(id(t.base), None))
	
	@staticmethod
	def __qname(name):
		if isinstance(name, QName):
			return name
		if len(name.nsset) == 0:
			return QName(Namespace("", CONSTANT_Namespace), name.name)
		return QName(stripVersion(name.nsset[0]), name.name)
	
	def qname(self, name):
		if (not self.nameToQName.has_key(id(name))):
			try:
				result = self.__qname(name)
			except:
				print dir(name)
				raise
			self.qnameToName[id(result)] = name
			self.nameToQName[id(name)] = result
			return result
		return self.nameToQName[id(name)]
	
	def parseTraits(self, t, baseTraits=None):
		lastBaseTraitsSlotId = 0 if baseTraits is None else baseTraits.nextSlotId
		namecount = self.data.readU30()
		t.members = [ None ] * namecount
		for i in range(0, namecount):
			name_index = self.data.readU30()
			name = self.names[name_index]
			name = self.qname(name)
			bindingOffset = self.data.pos
			tag = self.data.readU8()
			kind = tag & 0xf
			member = None
			if kind in [TRAIT_Slot, TRAIT_Const, TRAIT_Class]:
				member = SlotInfo()
				member.fileOffset = bindingOffset
				memberId = self.data.readU30()
				member.id = (memberId - 1) if memberId != 0 else (len(t.slots) + lastBaseTraitsSlotId)
				memberIndex = member.id - lastBaseTraitsSlotId
				while len(t.slots) <= memberIndex:
					t.slots.append(None)
				t.slots[member.id - lastBaseTraitsSlotId] = member
				t.nextSlotId = max(t.nextSlotId, member.id + 1)
				if kind in [TRAIT_Slot, TRAIT_Const]:
					member.type = self.names[self.data.readU30()]
					index = self.data.readU30()
					if index:
						deftable = self.defaults[self.data.readU8()]
						member.value = deftable[0][index]
						if deftable[1] == CTYPE_NAMESPACE:
							assert(isinstance(member.value, Namespace))
							member.value.srcname = name.name
				else:
					member.value = self.classes[self.data.readU30()]
					member.value.qname = name
			elif kind in [TRAIT_Method, TRAIT_Getter, TRAIT_Setter]:
				self.data.readU30()	# disp_id, ignored
				methid = self.data.readU30()
				member = self.methods[methid]
				t.tmethods.append(member)
				member.id = methid
				member.final = (tag & ATTR_final) != 0
				member.override = (tag & ATTR_override) != 0
			member.kind = kind
			member.name = name
			t.members[i] = member
			t.names[str(name)] = member
			
			if (tag & ATTR_metadata) != 0:
				mdCount = self.data.readU30()
				member.metadata = [ None ] * mdCount
				for j in range(0, mdCount):
					member.metadata[j] = self.metadata[self.data.readU30()]
				# stash class metadata in the ctraits and itraits too, makes it much easier later
				if kind == TRAIT_Class:
					member.value.metadata = member.metadata
					member.value.itraits.metadata = member.metadata

	def find_nativeinfo(self, m, ni):
		if m != None:
			for md in m:
				if md.name == "native":
					if md.attrs.has_key("script"):
						raise Error("native scripts are no longer supported; please use a native class instead and wrap with AS3 code as necessary.")
					if md.attrs.has_key("cls"):
						ni.set_class(md.attrs["cls"])
					if md.attrs.has_key("instance"):
						ni.set_instance(md.attrs["instance"])
					if md.attrs.has_key("methods"):
						v = md.attrs["methods"]
						ni.gen_method_map = True
						if v != "auto":
							ni.method_map_name = v
					if md.attrs.has_key("constsetters"):
						v = md.attrs.get("constsetters")
						if (v == "true"):
							ni.constSetters = True
						elif (v != "false"):
							raise Error(u'native metadata specified illegal value, "%s" for constsetters field.	 Value must be "true" or "false".' % unicode(v))
					if (ni.class_name == None) and (ni.instance_name == None):
						raise Error("native metadata must specify (cls,instance)")

	def find_class_nativeinfo(self, t):
		ni = NativeInfo()
		self.find_nativeinfo(t.metadata, ni)
		if ni.instance_name != None and t.itraits.is_interface:
			raise Error("interfaces may not specify native(instance)")
		ni.validate()
		return ni
		
	def parseClassInfos(self):
		count = len(self.instances)
		self.classes = [ None ] * count
		for i in range(0, count):
			itraits = self.instances[i]
			tname = QName(itraits.name.ns, (str(itraits.name.name) + "$"))
			t = Traits(tname)
			self.classes[i] = t
			t.init = self.methods[self.data.readU30()]
			t.base = "Class"
			t.itraits = itraits
			t.init.name = str(t.itraits.name) + "$cinit"
			t.init.kind = TRAIT_Method
			self.parseTraits(t)

	def parseScriptInfos(self):
		count = self.data.readU30()
		self.scripts = [ None ] * count
		for i in range(0, count):
			tname = self.scriptName + "_script_" + str(i)
			t = Traits(tname)
			self.scripts[i] = t
			t.init = self.methods[self.data.readU30()]
			t.base = self.names[0]
			t.itraits = None
			t.init.name = t.name + "$init"
			t.init.kind = TRAIT_Method	    
			self.parseTraits(t)

	def parseMethodBodies(self):
		count = self.data.readU30()
		for i in range(0, count):
			m = self.methods[self.data.readU30()]
			m.max_stack = self.data.readU30()
			m.local_count = self.data.readU30()
			initScopeDepth = self.data.readU30()
			maxScopeDepth = self.data.readU30()
			m.max_scope = maxScopeDepth - initScopeDepth
			code_length = self.data.readU30()
			m.code = self.data.readBytes(code_length)
			ex_count = self.data.readU30()
			for j in range(0, ex_count):
				frm = self.data.readU30()
				to = self.data.readU30()
				target = self.data.readU30()
				type = self.names[self.data.readU30()]
				name = self.names[self.data.readU30()];
			m.activation = Traits(None)
			self.parseTraits(m.activation)

''' end of 3rd-party code'''

