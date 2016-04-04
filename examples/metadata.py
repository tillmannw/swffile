#!/usr/bin/env python

import sys
import pprint
import swffile

def main():

	f = swffile.Flash(sys.argv[1])

	print "\nHeader:"
	print "     Version: %d" % f.header.Version
	print "  FileLength: %s" % f.header.FileLength
	print "       Twips: %d x %d" % (f.header.FrameSize.Xmax - f.header.FrameSize.Xmin, f.header.FrameSize.Ymax - f.header.FrameSize.Ymin)
	print "      Pixels: %d x %d" % (f.header.MovieWidth, f.header.MovieHeight)
	print "   FrameRate: %d" % f.header.FrameRate
	print "  FrameCount: %d" % f.header.FrameCount

	print "\nFlags: %08x" % f.Flags.Value
	print "  UseDirectBlit: ", f.Flags.UseDirectBlit
	print "         UseGPU: ", f.Flags.UseGPU
	print "    HasMetadata: ", f.Flags.HasMetadata
	print "  ActionScript3: ", f.Flags.ActionScript3
	print "     UseNetwork: ", f.Flags.UseNetwork

	if hasattr(f, 'ScriptLimits'):
		print "\nScriptLimits:"
		print "     MaxRecursionDepth: ", f.ScriptLimits.MaxRecursionDepth
		print "  ScriptTimeoutSeconds: ", f.ScriptLimits.ScriptTimeoutSeconds

	print "\nBackgroundColor:"
	print "    BackgroundColor.Red: ", f.SetBackgroundColor.BackgroundColor.Red
	print "  BackgroundColor.Green: ", f.SetBackgroundColor.BackgroundColor.Green
	print "   BackgroundColor.Blue: ", f.SetBackgroundColor.BackgroundColor.Blue

	if hasattr(f, 'ProductInfo'):
		print "\nProductInfo:"
		print "              ProductId: ", f.ProductInfo.ProductId
		print "                Edition: ", f.ProductInfo.Edition
		print "           MajorVersion: ", f.ProductInfo.MajorVersion
		print "           MinorVersion: ", f.ProductInfo.MinorVersion
		print "               BuildLow: ", f.ProductInfo.BuildLow
		print "              BuildHigh: ", f.ProductInfo.BuildHigh
		print "        CompilationDate: ", f.ProductInfo.CompilationDate
		print "  CompilationDateString: ", f.ProductInfo.CompilationDateString

	print "\nSymbolClass:"
	print "  NumSymbols: ", f.SymbolClass.NumSymbols
	for i in range(f.SymbolClass.NumSymbols):
		print "    %04x: %s" % (f.SymbolClass.Tags[i], f.SymbolClass.Names[i])

	for DoABC in f.DoABC:
		print "\nDoABC:"
		print "  Name:", DoABC.Name.rstrip('\0')
		print "  Flags: %08x" % DoABC.Flags.Value
		print "    kDoAbcLazyInitializeFlag: ", DoABC.Flags.kDoAbcLazyInitializeFlag
		abc = f.disassembleABC(DoABC)
		print "  ABC metadata:"
		print "    major:minor version: %s:%s" % (abc.major, abc.minor)
		print "    scriptName: %s" % abc.scriptName[:-1]
		print "    publicNs: %s" % abc.publicNs

	return

if __name__ == "__main__":
    main()
