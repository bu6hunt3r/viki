#!/usr/bin/env python

'''
Description:      Assembles a file using nasm, extracts shellcode bytes, and compiles a C binary
'''

import sys
import os
from subprocess import check_output, PIPE, STDOUT
from argparse import ArgumentParser

__version__ = "0.1"

class ShellBuild:
	def __init__(self):
		args = self._arguments()

		self.dir = args.d + '/'
		if not os.path.exists(args.d):
			os.makedirs(args.d)

		self.file = args.file
		self.clean = args.file.split('.')[0]
		self.obj = self.dir + self.clean + '.o'
		self.bin = self.dir + self.clean + '.bin'
		self.txt = self.dir + self.clean + '.txt'
		self.elf = self.dir + self.clean + '.elf'
		self.c = self.dir + self.clean + '.c'
		self.out = self.dir + self.clean + '.out'
		self.arch = 'elf' + str(args.x)

	def run(self):
		print "Assembling %s (%s)" % (self.file, self.arch)
		err = self.build()
		if err:
			print err

		print "Parsing disassembly"
		shellcode, binary, code = self.parse()

		print "Linking into %s" % (self.elf)
		err = self.link()
		if err:
			print err

		for line in code:
			print "\t", line

		cdata = 'unsigned char shellcode[] = \n\t' + "\n\t".join(code) +  ';\n\nint main(void)\n{\n\t(*(void(*)()) shellcode)();\n\n\treturn 0;\n}'
		self._write_file(self.c, cdata)
		self._write_file(self.txt, shellcode)
		self._write_file(self.bin, binary, 'wb')
		print "Compiling to ", self.out
		print check_output(["gcc", "-m64", "-z", "execstack", "-fno-stack-protector", "-o", self.out, self.c])

		print
		print shellcode

	def _write_file(self, filename, filedata, mode = 'w'):
		print "Writing to %s (%d bytes)" % (filename, len(filedata))
		with open(filename, mode) as fhs:
			fhs.write(filedata)

	def _arguments(self):
		parser = ArgumentParser(description='shellbuild ' + __version__)
		parser.add_argument('-x', metavar="32/64", default=32, type=int, help="Assembly architecture (32 or 64 bit)")
		parser.add_argument('-d', metavar="build", default='build', help="Output build directory")
		parser.add_argument('file', help="The assembly code filename")
		return parser.parse_args()

	def link(self):
		return check_output(['ld', '-o', self.elf, self.obj])

	def build(self):
		return check_output(['nasm', '-f', self.arch, '-o', self.obj, self.file])

	def parse(self):
		lines = check_output(['objdump', '-d', '--disassembler-options=addr64', self.obj])
		lines = lines.split('Disassembly of section')[1]
		lines = lines.split('\n')[3:]

		shellcode = ""
		binary = ""
		code = []

		for line in lines:
			line = line.strip()
			if not line:
				continue

			tabs = line.split('\t')
			if (len(tabs) < 2):
				continue
			bytes = tabs[1].strip()

			instruction = "."
			if (len(tabs) == 3):
				instruction = tabs[2].strip()

			bytes = bytes.split(' ')
			shellcodeline = ""
			for byte in bytes:
				shellcodeline += "\\x" + byte

			shellcode += shellcodeline

			c = '%-*s/* %s */' % (32, '"'+shellcodeline+'"', instruction)
			code.append(c)

		binary = shellcode.decode("string-escape")
		return shellcode, binary, code

if __name__ == '__main__':
	sb = ShellBuild()
	sb.run()
