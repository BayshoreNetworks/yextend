/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014-2015 by Bayshore Networks, Inc. All Rights Reserved.
 *
 * This file is part of yextend.
 *
 * yextend is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * yextend is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with yextend.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#include "filedata.h"

using namespace std;

map<string, int> FileDataPatterns;
map<int, int> FileDataPatternOffset;
map<int, string> FileDataPatternMap;

class __InitFileData_t
{
	public:
		__InitFileData_t();
		~__InitFileData_t();
};
__InitFileData_t __InitFileData;


/**********************************
__InitFileData_t::__InitFileData_t
**********************************/

__InitFileData_t::__InitFileData_t()
{
	/*
	 * the following numerical indexing order cannot change or logic in:
	 * 
	 * 		FileDissect
	 * 		DocumentParser
	 * 		ContentSecurityScan
	 * 		
	 * will break. It is entirely OK to add new stuff - just make sure the indexes
	 * get incremented properly.
	 * 
	 * Index 26000 is special. If our increments ever get that high up there
	 * DO NOT use 26000. Even though I may not be alive by the time we get up
	 * that high :-)
	 * 
	 * Index 65535 is also special in that it represents the use case where
	 * we could not detect the file type yet still want to inspect content.
	 * So it is used for an unclassified binary file type
	 * 
	 * Index 65534 is special in that I had to push the zip file pattern
	 * down in the stack such that zip derivatives are detected before
	 * a pure vanilla zip file is identified
	 * 
	 * The value in FileDataPatternOffset will be used in FileDissect and will
	 * tell that process where (the offset) to start looking for a match
	 * on the data pattern
	 * 
	 * A stanza here is defined as:
	 * 
	 * 		FileDataPatterns["abc"] = X;
	 * 		FileDataPatternMap[X] = "DEF";
	 * 		FileDataPatternOffset[X] = Y;
	 * 
	 * When you add a new stanza that covers an existing data type make sure
	 * you update the relevant is_XYZ function where XYZ is the data type
	 * or something close to it, example for PDF is:
	 * 
	 * 		is_pdf(int ix)
	 */

	FileDataPatterns["encrypted"] = 0;
	FileDataPatternMap[0] = "Goodwill guess .... Encrypted file detected";
	FileDataPatternOffset[0] = 0;

	FileDataPatterns["25504446"] = 1;
	FileDataPatternMap[1] = "Adobe PDF";
	FileDataPatternOffset[1] = 0;

	FileDataPatterns["255044462d312e"] = 2;
	FileDataPatternMap[2] = "Adobe PDF";
	FileDataPatternOffset[2] = 0;

	FileDataPatterns["504b030414000600080000002100"] = 3;
	FileDataPatternMap[3] = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)";
	FileDataPatternOffset[3] = 0;

	FileDataPatterns["d0cf11e0a1b11ae1"] = 4;
	FileDataPatternMap[4] = "Microsoft Office document (DOC PPT XLS)";
	FileDataPatternOffset[4] = 0;

	FileDataPatterns["d0cf11e0a1b11ae100000000000000000000000000000000"] = 5;
	FileDataPatternMap[5] = "Microsoft Office document (DOC PPT XLS)";
	FileDataPatternOffset[5] = 0;

	FileDataPatterns["52457e5e"] = 6;
	FileDataPatternMap[6] = "RAR Archive";
	FileDataPatternOffset[6] = 0;

	FileDataPatterns["526172211a0700cf"] = 7;
	FileDataPatternMap[7] = "RAR Archive";
	FileDataPatternOffset[7] = 0;

	FileDataPatterns["526172211a0700ffffffcf"] = 8;
	FileDataPatternMap[8] = "RAR Archive";
	FileDataPatternOffset[8] = 0;

	FileDataPatterns["526172211a07005a"] = 9;
	FileDataPatternMap[9] = "RAR Archive (Part 1 of Multiple Files)";
	FileDataPatternOffset[9] = 0;

	FileDataPatterns["526172211a070019"] = 10;
	FileDataPatternMap[10] = "RAR Archive (Subsequent Part of Multiple Files)";
	FileDataPatternOffset[10] = 0;

	FileDataPatterns["526172211a0700ce"] = 11;
	FileDataPatternMap[11] = "Encrypted RAR Archive";
	FileDataPatternOffset[11] = 0;

	FileDataPatterns["526172211a0700ffffffce"] = 12;
	FileDataPatternMap[12] = "Encrypted RAR Archive";
	FileDataPatternOffset[12] = 0;

	FileDataPatterns["526172211a07005b"] = 13;
	FileDataPatternMap[13] = "Encrypted RAR Archive (Part 1 of Multiple Files)";
	FileDataPatternOffset[13] = 0;

	FileDataPatterns["526172211a070018"] = 14;
	FileDataPatternMap[14] = "Encrypted RAR Archive (Subsequent Part of Multiple Files)";
	FileDataPatternOffset[14] = 0;

	/*
    FileDataPatterns["504b0304"] = 15;
    FileDataPatternMap[15] = "Zip or Jar Archive";
    FileDataPatternOffset[15] = 0;
	 */

	FileDataPatterns["5f27a889"] = 16;
	FileDataPatternMap[16] = "Jar Archive";
	FileDataPatternOffset[16] = 0;

	FileDataPatterns["1fffffff8b08"] = 17;
	FileDataPatternMap[17] = "GZIP Archive";
	FileDataPatternOffset[17] = 0;

	FileDataPatterns["1f8b08"] = 18;
	FileDataPatternMap[18] = "GZIP Archive";
	FileDataPatternOffset[18] = 0;

	FileDataPatterns["1f9d90"] = 19;
	FileDataPatternMap[19] = "Compressed Tape Archive (TAR.Z)";
	FileDataPatternOffset[19] = 0;

	FileDataPatterns["1fa0"] = 20;
	FileDataPatternMap[20] = "Compressed Tape Archive (TAR.Z)";
	FileDataPatternOffset[20] = 0;

	FileDataPatterns["377abcaf271c"] = 21;
	FileDataPatternMap[21] = "7-Zip compressed file";
	FileDataPatternOffset[21] = 0;

	// <html
	FileDataPatterns["3c68746d6c"] = 22;
	FileDataPatternMap[22] = "HTML File";
	FileDataPatternOffset[22] = 0;
	// <HTML
	FileDataPatterns["3c48544d4c"] = 23;
	FileDataPatternMap[23] = "HTML File";
	FileDataPatternOffset[23] = 0;
	// <!DOCTYPE html
	FileDataPatterns["3c21444f43545950452068746d6c"] = 24;
	FileDataPatternMap[24] = "HTML File";
	FileDataPatternOffset[24] = 0;
	// <!DOCTYPE HTML
	FileDataPatterns["3c21444f43545950452048544d4c"] = 25;
	FileDataPatternMap[25] = "HTML File";
	FileDataPatternOffset[25] = 0;

	// DOS / MZ executable
	FileDataPatterns["4d5a"] = 26;
	FileDataPatternMap[26] = "Windows Executable";
	FileDataPatternOffset[26] = 0;
	FileDataPatterns["004d5a"] = 27;
	FileDataPatternMap[27] = "Windows Executable";
	FileDataPatternOffset[27] = 0;
	FileDataPatternMap[26000] = "Windows - Portable Executable";

	/*
	 * Microsoft Office Open XML Format generated on Linux with
	 * openoffice and/or libreoffice, this pattern should cover
	 * .docx - .pptx - .xlsx
	 */
	FileDataPatterns["504b0304140008080800"] = 28;
	FileDataPatternMap[28] = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)";
	FileDataPatternOffset[28] = 0;

	// Generic text file
	FileDataPatterns["text"] = 29;
	FileDataPatternMap[29] = "ASCII Text File";
	FileDataPatternOffset[29] = 0;

	FileDataPatterns["526172211a070015"] = 30;
	FileDataPatternMap[30] = "Encrypted RAR Archive";
	FileDataPatternOffset[30] = 0;

	// php source code
	// <?php
	FileDataPatterns["3c3f706870"] = 31;
	FileDataPatternMap[31] = "PHP Source Code";
	FileDataPatternOffset[31] = 0;
	// short tags - <?
	FileDataPatterns["3c3f"] = 32;
	FileDataPatternMap[32] = "PHP Source Code";
	FileDataPatternOffset[32] = 0;

	// some images
	FileDataPatterns["ffd8ffe0"] = 33;
	FileDataPatternMap[33] = "JPEG image file";
	FileDataPatternOffset[33] = 0;
	FileDataPatterns["ffd8ffe1"] = 34;
	FileDataPatternMap[34] = "JPEG (EXIF) image file";
	FileDataPatternOffset[34] = 0;
	FileDataPatterns["ffd8ffe8"] = 35;
	FileDataPatternMap[35] = "JPEG (SPIFF) image file";
	FileDataPatternOffset[35] = 0;
	FileDataPatterns["0000000c6a502020"] = 36;
	FileDataPatternMap[36] = "JPEG2000 image file";
	FileDataPatternOffset[36] = 0;
	FileDataPatterns["424d"] = 37;
	FileDataPatternMap[37] = "Bitmap image file";
	FileDataPatternOffset[37] = 0;
	FileDataPatterns["47494638"] = 38;
	FileDataPatternMap[38] = "GIF image file";
	FileDataPatternOffset[38] = 0;
	FileDataPatterns["4d4d002a"] = 39;
	FileDataPatternMap[39] = "TIFF image file";
	FileDataPatternOffset[39] = 0;
	FileDataPatterns["4d4d002b"] = 40;
	FileDataPatternMap[40] = "TIFF image file";
	FileDataPatternOffset[40] = 0;
	FileDataPatterns["492049"] = 41;
	FileDataPatternMap[41] = "TIFF image file";
	FileDataPatternOffset[41] = 0;
	FileDataPatterns["49492a00"] = 42;
	FileDataPatternMap[42] = "TIFF image file";
	FileDataPatternOffset[42] = 0;
	FileDataPatterns["89504e470d0a1a0a"] = 43;
	FileDataPatternMap[43] = "PNG image file";
	FileDataPatternOffset[43] = 0;

	/*
	 * Open Document Format for Office Applications (ODF),
	 * also known as OpenDocument
	 * 
	 * .odt and .fodt for word processing (text) documents
	 * .ods and .fods for spreadsheets
	 * .odp and .fodp for presentations
	 * .odb for databases
	 * .odg and .fodg for graphics
	 * .odf for formulae, mathematical equations
	 * 
	 * should cover modern-day versions of
	 * 
	 * openoffice
	 * libreoffice 
	 */
	FileDataPatterns["504b0304140000080000"] = 44;
	FileDataPatternMap[44] = "Open Document Format (ODF) document";
	FileDataPatternOffset[44] = 0;

	// xml
	FileDataPatterns["3c3f786d6c"] = 45;
	FileDataPatternMap[45] = "XML Document";
	FileDataPatternOffset[45] = 0;

	// tar - ustar at offset 0x101
	FileDataPatterns["7573746172"] = 46;
	FileDataPatternMap[46] = "TAR Archive";
	FileDataPatternOffset[46] = 257;

	// pcap FileDataPatterns
	FileDataPatterns["a1b2c3d4"] = 47;
	FileDataPatternMap[47] = "PCAP file";
	FileDataPatternOffset[47] = 0;

	FileDataPatterns["d4c3b2a1"] = 48;
	FileDataPatternMap[48] = "PCAP file";
	FileDataPatternOffset[48] = 0;

	FileDataPatterns["d4c3b2a1020004000000000000000000ffff000001000000"] = 49;
	FileDataPatternMap[49] = "PCAP file";
	FileDataPatternOffset[49] = 0;

	/*
	 * new officex pattern encountered at a client
	 * site. They must be creating officex files with
	 * either a non MS product or a diff version
	 * than what we have encountered thus far
	 */
	FileDataPatterns["504b0304140002000800"] = 50;
	FileDataPatternMap[50] = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)";
	FileDataPatternOffset[50] = 0;

	// MATLAB 5
	FileDataPatterns["4d41544c41422035"] = 51;
	FileDataPatternMap[51] = "MATLAB 5.X";
	FileDataPatternOffset[51] = 0;

	// MATLAB 7
	FileDataPatterns["4d41544c41422037"] = 52;
	FileDataPatternMap[52] = "MATLAB 7.X";
	FileDataPatternOffset[52] = 0;

	// CATIA Model
	FileDataPatterns["56355f434656320000"] = 53;
	FileDataPatternMap[53] = "CATIA Model";
	FileDataPatternOffset[53] = 0;

	// Mujahideen Secrets 2 encrypted file
	FileDataPatterns["005c41b1ff"] = 54;
	FileDataPatternMap[54] = "Mujahideen Secrets 2 encrypted file";
	FileDataPatternOffset[54] = 0;

	// Generic AutoCAD
	FileDataPatterns["41433130"] = 55;
	FileDataPatternMap[55] = "AutoCAD Drawing";
	FileDataPatternOffset[55] = 0;

	// Lotus stuff
	FileDataPatterns["1a0000040000"] = 56;
	FileDataPatternMap[56] = "Lotus Notes Database";
	FileDataPatternOffset[56] = 0;

	FileDataPatterns["1a0000"] = 57;
	FileDataPatternMap[57] = "Lotus Notes Database Template";
	FileDataPatternOffset[57] = 0;

	// Outlook / some email stuff
	FileDataPatterns["2142444e"] = 58;
	FileDataPatternMap[58] = "Microsoft Outlook Personal Folder File";
	FileDataPatternOffset[58] = 0;

	FileDataPatterns["46726f6d203f3f3f"] = 59;
	FileDataPatternMap[59] = "Generic E-Mail (EML) File";
	FileDataPatternOffset[59] = 0;

	FileDataPatterns["46726f6d202020"] = 60;
	FileDataPatternMap[60] = "Generic E-Mail (EML) File";
	FileDataPatternOffset[60] = 0;

	FileDataPatterns["46726f6d3a20"] = 61;
	FileDataPatternMap[61] = "Generic E-Mail (EML) File";
	FileDataPatternOffset[61] = 0;

	FileDataPatterns["46726f6d"] = 62;
	FileDataPatternMap[62] = "Generic E-Mail (EML) File";
	FileDataPatternOffset[62] = 0;

	FileDataPatterns["52657475726e2d50"] = 63;
	FileDataPatternMap[63] = "Generic E-Mail (EML) File";
	FileDataPatternOffset[63] = 0;

	FileDataPatterns["813284c18505d011b29000aa003cf676"] = 64;
	FileDataPatternMap[64] = "Outlook Express address book (Win95)";
	FileDataPatternOffset[64] = 0;

	FileDataPatterns["cfad12fe"] = 65;
	FileDataPatternMap[65] = "Outlook Express E-Mail Folder";
	FileDataPatternOffset[65] = 0;

	FileDataPatterns["9ccbcb8d1375d211955800c04f7956a4"] = 66;
	FileDataPatternMap[66] = "Outlook Address File";
	FileDataPatternOffset[66] = 0;

	FileDataPatterns["9ccbcb8d1375d211"] = 67;
	FileDataPatternMap[67] = "Outlook Address File";
	FileDataPatternOffset[67] = 0;

	// PGP / GPG files
	FileDataPatterns["988d04"] = 68;
	FileDataPatternMap[68] = "PGP/GPG Public Key File - RSA Key Length 1024";
	FileDataPatternOffset[68] = 0;

	FileDataPatterns["99010d04"] = 69;
	FileDataPatternMap[69] = "PGP/GPG Public Key File - RSA Key Length 2048";
	FileDataPatternOffset[69] = 0;

	FileDataPatterns["99018d04"] = 70;
	FileDataPatternMap[70] = "PGP/GPG Public Key File - RSA Key Length 3072";
	FileDataPatternOffset[70] = 0;

	FileDataPatterns["99020d04"] = 71;
	FileDataPatternMap[71] = "PGP/GPG Public Key File - RSA Key Length 4096";
	FileDataPatternOffset[71] = 0;

	FileDataPatterns["9501d804"] = 72;
	FileDataPatternMap[72] = "PGP/GPG Private Key File - RSA Key Length 1024";
	FileDataPatternOffset[72] = 0;

	FileDataPatterns["95039804"] = 73;
	FileDataPatternMap[73] = "PGP/GPG Private Key File - RSA Key Length 2048";
	FileDataPatternOffset[73] = 0;

	FileDataPatterns["95055804"] = 74;
	FileDataPatternMap[74] = "PGP/GPG Private Key File - RSA Key Length 3072";
	FileDataPatternOffset[74] = 0;

	FileDataPatterns["95071804"] = 75;
	FileDataPatternMap[75] = "PGP/GPG Private Key File - RSA Key Length 4096";
	FileDataPatternOffset[75] = 0;

	FileDataPatterns["9501fe04"] = 76;
	FileDataPatternMap[76] = "PGP/GPG Private Key File (password protected) - RSA Key Length 1024";
	FileDataPatternOffset[76] = 0;

	FileDataPatterns["9503be04"] = 77;
	FileDataPatternMap[77] = "PGP/GPG Private Key File (password protected) - RSA Key Length 2048";
	FileDataPatternOffset[77] = 0;

	FileDataPatterns["95057e04"] = 78;
	FileDataPatternMap[78] = "PGP/GPG Private Key File (password protected) - RSA Key Length 3072";
	FileDataPatternOffset[78] = 0;

	FileDataPatterns["95073d04"] = 79;
	FileDataPatternMap[79] = "PGP/GPG Private Key File (password protected) - RSA Key Length 4096";
	FileDataPatternOffset[79] = 0;

	FileDataPatterns["848c03"] = 80;
	FileDataPatternMap[80] = "PGP/GPG Encrypted File - RSA Key Length 1024";
	FileDataPatternOffset[80] = 0;

	FileDataPatterns["85010c03"] = 81;
	FileDataPatternMap[81] = "PGP/GPG Encrypted File - RSA Key Length 2048";
	FileDataPatternOffset[81] = 0;

	FileDataPatterns["85018c03"] = 82;
	FileDataPatternMap[82] = "PGP/GPG Encrypted File - RSA Key Length 3072";
	FileDataPatternOffset[82] = 0;

	FileDataPatterns["85020c03"] = 83;
	FileDataPatternMap[83] = "PGP/GPG Encrypted File - RSA Key Length 4096";
	FileDataPatternOffset[83] = 0;

	// -----BEGIN PGP MESSAGE-----
	FileDataPatterns["2d2d2d2d2d424547494e20504750204d4553534147452d2d2d2d2d"] = 84;
	FileDataPatternMap[84] = "PGP Encrypted Message (ciphertext)";
	FileDataPatternOffset[84] = 0;

	// -----BEGIN PGP PUBLIC KEY BLOCK-----
	FileDataPatterns["2d2d2d2d2d424547494e20504750205055424c4943204b455920424c4f434b2d2d2d2d2d"] = 85;
	FileDataPatternMap[85] = "PGP Public Key Block";
	FileDataPatternOffset[85] = 0;

	// -----BEGIN PGP PRIVATE KEY BLOCK-----
	FileDataPatterns["2d2d2d2d2d424547494e205047502050524956415445204b455920424c4f434b2d2d2d2d2d"] = 86;
	FileDataPatternMap[86] = "PGP Private Key Block";
	FileDataPatternOffset[86] = 0;

	// pcap FileDataPatterns
	FileDataPatterns["34cdb2a1"] = 87;
	FileDataPatternMap[87] = "PCAP file";
	FileDataPatternOffset[87] = 0;

	FileDataPatterns["a1b2cd34"] = 88;
	FileDataPatternMap[88] = "PCAP file";
	FileDataPatternOffset[88] = 0;

	FileDataPatterns["0a0d0d0a"] = 89;
	FileDataPatternMap[89] = "PCAPNG file";
	FileDataPatternOffset[89] = 0;

	// Windows Policy Administrative Template files
	FileDataPatterns["fffe43004c004100530053002000"] = 90;
	FileDataPatternMap[90] = "Windows Policy Administrative Template";
	FileDataPatternOffset[90] = 0;

	FileDataPatterns["3b"] = 91;
	FileDataPatternMap[91] = "Windows Policy Administrative Template";
	FileDataPatternOffset[91] = 0;

	FileDataPatterns["434c41535320"] = 92;
	FileDataPatternMap[92] = "Windows Policy Administrative Template";
	FileDataPatternOffset[92] = 0;

	FileDataPatterns["fffe3c003f0078006d006c0020007600"] = 93;
	FileDataPatternMap[93] = "Windows Group Policy Administrative Template";
	FileDataPatternOffset[93] = 0;

	// extension MRP
	FileDataPatterns["4d525047"] = 94;
	FileDataPatternMap[94] = "China Mobile Application";
	FileDataPatternOffset[94] = 0;    

	// rare but valid pattern for DOS / MZ executable
	FileDataPatterns["5a4d"] = 95;
	FileDataPatternMap[95] = "Windows Executable";
	FileDataPatternOffset[95] = 0;

	/*
	 * different patterns of binaries/executables ...
	 */
	FileDataPatterns["7f454c46"] = 96;
	FileDataPatternMap[96] = "ELF Executable";
	FileDataPatternOffset[96] = 0;

	FileDataPatterns["feedface"] = 97;
	FileDataPatternMap[97] = "Mach-O 32-Bit Big Endian";
	FileDataPatternOffset[97] = 0;

	FileDataPatterns["cefaedfe"] = 98;
	FileDataPatternMap[98] = "Mach-O 32-Bit Little Endian";
	FileDataPatternOffset[98] = 0;

	FileDataPatterns["feedfacf"] = 99;
	FileDataPatternMap[99] = "Mach-O 64-Bit Big Endian";
	FileDataPatternOffset[99] = 0;

	FileDataPatterns["cffaedfe"] = 100;
	FileDataPatternMap[100] = "Mach-O 64-Bit Little Endian";
	FileDataPatternOffset[100] = 0;

	/*
	 * Compiled Java class files (bytecode) and Mach-O binaries start with hex CAFEBABE 
	 * When compressed with Pack200 the bytes are changed to CAFED00D
	 */
	FileDataPatterns["cafebabe"] = 101;
	FileDataPatternMap[101] = "Java Bytecode or Mach-O FAT Binary";
	FileDataPatternOffset[101] = 0;

	FileDataPatterns["cafed00d"] = 102;
	FileDataPatternMap[102] = "Java Bytecode (Pack200 compression)";
	FileDataPatternOffset[102] = 0;

	FileDataPatterns["aced"] = 103;
	FileDataPatternMap[103] = "Java Serialization Data";
	FileDataPatternOffset[103] = 0;

	FileDataPatterns["beefcace"] = 104;
	FileDataPatternMap[104] = "Microsoft .Net Resource File";
	FileDataPatternOffset[104] = 0;

	FileDataPatterns["435753"] = 105;
	FileDataPatternMap[105] = "Shockwave Flash File (SWF)";
	FileDataPatternOffset[105] = 0;

	FileDataPatterns["465753"] = 106;
	FileDataPatternMap[106] = "Shockwave Flash File (SWF)";
	FileDataPatternOffset[106] = 0;

	FileDataPatterns["464c56"] = 107;
	FileDataPatternMap[107] = "Flash Video File (FLV)";
	FileDataPatternOffset[107] = 0;

	FileDataPatterns["64383a616e6e6f756e6365"] = 108;
	FileDataPatternMap[108] = "Torrent File";
	FileDataPatternOffset[108] = 0;

	// more zip patterns
	FileDataPatterns["504b0506"] = 109;
	FileDataPatternMap[109] = "Zip Archive";
	FileDataPatternOffset[109] = 0;

	FileDataPatterns["504b0708"] = 110;
	FileDataPatternMap[110] = "Zip Archive";
	FileDataPatternOffset[110] = 0;

	FileDataPatterns["504b537058"] = 111; // PKSpX in ASCII
	FileDataPatternMap[111] = "PKSFX Self-Extracting Archive";
	FileDataPatternOffset[111] = 526;

	FileDataPatterns["504b4c495445"] = 112; // PKLITE in ASCII
	FileDataPatternMap[112] = "PKLITE Compressed ZIP Archive";
	FileDataPatternOffset[112] = 30;

	// Puffer encrypted
	FileDataPatterns["50554658"] = 113; // PUFX in ASCII
	FileDataPatternMap[113] = "Puffer Encrypted Archive";
	FileDataPatternOffset[113] = 0;

	FileDataPatterns["426567696e2050756666657220446174610d0a"] = 114; // Begin Puffer Data.. in ASCII
	FileDataPatternMap[114] = "Puffer ASCII-Armored Encrypted Archive";
	FileDataPatternOffset[114] = 0;

	// VirtualBox Disk Image
	FileDataPatterns["3c3c3c20"] = 115;
	FileDataPatternMap[115] = "VirtualBox Disk Image (VDI)";
	FileDataPatternOffset[115] = 0;

	// VMDK
	FileDataPatterns["434f5744"] = 116;
	FileDataPatternMap[116] = "VMware 3 Virtual Disk";
	FileDataPatternOffset[116] = 0;

	FileDataPatterns["23204469736b2044"] = 117;
	FileDataPatternMap[117] = "VMware 4 Virtual Disk";
	FileDataPatternOffset[117] = 0;

	FileDataPatterns["4b444d"] = 118;
	FileDataPatternMap[118] = "VMware 4 Virtual Disk";
	FileDataPatternOffset[118] = 0;

	// another TIFF image
	FileDataPatterns["4d4d2a"] = 119;
	FileDataPatternMap[119] = "TIFF image file";
	FileDataPatternOffset[119] = 0;

	FileDataPatterns["49545346"] = 120;
	FileDataPatternMap[120] = "Compiled HTML";
	FileDataPatternOffset[120] = 0;

	FileDataPatterns["3f5f0300"] = 121;
	FileDataPatternMap[121] = "Windows Help File";
	FileDataPatternOffset[121] = 0;

	FileDataPatterns["4c4e0200"] = 122;
	FileDataPatternMap[122] = "Windows Help File";
	FileDataPatternOffset[122] = 0;

	FileDataPatterns["23212f"] = 123;
	FileDataPatternMap[123] = "Shell Script (shebang)";
	FileDataPatternOffset[123] = 0;

	// some media formats ...
	// MPEG Video file
	FileDataPatterns["000001b3"] = 124;
	FileDataPatternMap[124] = "MPEG Video file";
	FileDataPatternOffset[124] = 0;

	FileDataPatterns["000001ba"] = 125;
	FileDataPatternMap[125] = "MPEG Video file";
	FileDataPatternOffset[125] = 0;

	// ASF
	FileDataPatterns["3026b2758e66cf11"] = 126;
	FileDataPatternMap[126] = "Microsoft Windows Media Audio/Video File (ASF WMA WMV)";
	FileDataPatternOffset[126] = 0;

	// WAV
	FileDataPatterns["57415645"] = 127;
	FileDataPatternMap[127] = "Wave File (WAV)";
	FileDataPatternOffset[127] = 8;    

	// AVI
	FileDataPatterns["415649"] = 128;
	FileDataPatternMap[128] = "Audio Video Interleaved File (AVI)";
	FileDataPatternOffset[128] = 8; 

	// REAL
	FileDataPatterns["2e7261fd"] = 129;
	FileDataPatternMap[129] = "Real Audio Metadata File (RAM)";
	FileDataPatternOffset[129] = 0; 

	FileDataPatterns["2e524d46"] = 130;
	FileDataPatternMap[130] = "RealMedia File (RM)";
	FileDataPatternOffset[130] = 0;

	// Quicktime
	FileDataPatterns["6d6f6f76"] = 131;
	FileDataPatternMap[131] = "QuickTime Movie";
	FileDataPatternOffset[131] = 4;

	FileDataPatterns["6674797069736f6d"] = 132;
	FileDataPatternMap[132] = "QuickTime Movie (MP4)";
	FileDataPatternOffset[132] = 4;

	FileDataPatterns["6674797033677034"] = 133;
	FileDataPatternMap[133] = "QuickTime Movie (3GP)";
	FileDataPatternOffset[133] = 4;

	FileDataPatterns["667479706d6d7034"] = 134;
	FileDataPatternMap[134] = "QuickTime Movie (3GP)";
	FileDataPatternOffset[134] = 4;

	FileDataPatterns["667479704d344120"] = 135;
	FileDataPatternMap[135] = "QuickTime - Apple Lossless Audio Codec file (M4A)";
	FileDataPatternOffset[135] = 4;

	FileDataPatterns["667479704d345620"] = 136;
	FileDataPatternMap[136] = "QuickTime Movie (M4V)";
	FileDataPatternOffset[136] = 4;

	FileDataPatterns["667479706d703431"] = 137;
	FileDataPatternMap[137] = "QuickTime Movie (MP4)";
	FileDataPatternOffset[137] = 4;

	FileDataPatterns["667479706d703432"] = 138;
	FileDataPatternMap[138] = "QuickTime Movie (MP4)";
	FileDataPatternOffset[138] = 4;

	FileDataPatterns["6674797033677035"] = 139;
	FileDataPatternMap[139] = "QuickTime Movie (MP4)";
	FileDataPatternOffset[139] = 4;

	FileDataPatterns["667479704d534e56"] = 140;
	FileDataPatternMap[140] = "QuickTime Movie (MP4)";
	FileDataPatternOffset[140] = 4;    

	FileDataPatterns["6674797071742020"] = 141;
	FileDataPatternMap[141] = "QuickTime Movie (MOV)";
	FileDataPatternOffset[141] = 4;

	FileDataPatterns["0000001866747970"] = 142;
	FileDataPatternMap[142] = "MPEG-4 Video File (3GP5)";
	FileDataPatternOffset[142] = 4;

	// -----BEGIN PGP SIGNATURE-----
	FileDataPatterns["2d2d2d2d2d424547494e20504750205349474e41545552452d2d2d2d2d"] = 143;
	FileDataPatternMap[143] = "PGP/GPG Signed Content";
	FileDataPatternOffset[143] = 0;



	/*
	 * zip
	 * 
	 * had to move this down in the food chain
	 * as it was conflicting with too many other
	 * legit formats that are zip based
	 */
	FileDataPatterns["504b0304"] = 65534;
	FileDataPatternMap[65534] = "Zip Archive";
	FileDataPatternOffset[65534] = 0;

	/*
	 * default response ...
	 * meaning we did not detect a file type so
	 * we will treat this as a generic and
	 * unclassified binary file type
	 */
	FileDataPatterns["unclassified-binary"] = 65535;
	FileDataPatternMap[65535] = "Unclassified Binary";
}

/***********************************
__InitFileData_t::~__InitFileData_t
***********************************/

__InitFileData_t::~__InitFileData_t()
{
	FileDataPatterns.clear();
	FileDataPatternOffset.clear();
	FileDataPatternMap.clear();
}


FileData::FileData() { }


std::string FileData::GetType(int ix) {
    return FileDataPatternMap[ix];
}

bool FileData::is_officex(int ix) {
	if ((ix == 3) || (ix == 28) || (ix == 50))
		return true;
	return false;
}

bool FileData::is_pcap(int ix) {
	if ((ix == 47) || (ix == 48) || (ix == 49) ||
		(ix == 87) || (ix == 88) || (ix == 89))
		return true;
	return false;
}

bool FileData::is_unclassified(int ix) {
	if (ix == 65535)
		return true;
	return false;
}

bool FileData::is_tar(int ix) {
	if (ix == 46)
		return true;
	return false;
}

bool FileData::is_xml(int ix) {
	if (ix == 45)
		return true;
	return false;
}

bool FileData::is_open_document_format(int ix) {
	if (ix == 44)
		return true;
	return false;
}

bool FileData::is_php(int ix) {
	if ((ix == 31) || (ix == 32))
		return true;
	return false;
}

bool FileData::is_rar(int ix) {
	return ix >= 6 && ix <= 14 || ix == 30;
}

bool FileData::is_win_exe(int ix) {
	if ((ix == 26) || (ix == 27) || (ix == 26000) || (ix == 95))
		return true;
	return false;
}

bool FileData::is_html(int ix) {
	if ((ix == 22) || (ix == 23) || (ix == 24) || (ix == 25))
		return true;
	return false;
}


bool FileData::is_gzip(int ix) {
	if ((ix == 17) || (ix == 18))
		return true;
	return false;
}

bool FileData::is_pdf(int ix) {
	if ((ix == 1) || (ix == 2))
		return true;
	return false;
}

bool FileData::is_office(int ix) {
	if ((ix == 4) || (ix == 5))
		return true;
	return false;
}

bool FileData::is_image(int ix) {
	if ((ix >= 33 && ix <= 43) || (ix == 119))
		return true;
	return false;
}

bool FileData::is_zip(int ix) {
	if ((ix == 65534) || (ix == 109) || (ix == 110) || (ix == 111) || (ix == 112)) {
		return true;
	}
	return false;
}

bool FileData::is_archive(int ix) {
	/*
	 * 65534 = zip
	 * 17 = gzip
	 * 18 = gzip
	 * 46 = tar
	 * is_rar() covers all known rar patterns
	 * 21 = 7-zip
	 */
    if ((is_zip(ix)) ||
        (is_gzip(ix)) ||
        (is_tar(ix)) ||
        (is_rar(ix)) ||
        (is_7zip(ix))
        )
        return true;
	return false;
}

bool FileData::is_matlab(int ix) {
	if (ix == 51 || ix == 52) {
		return true;
	}
	return false;
}

bool FileData::is_7zip(int ix) {
	if (ix == 21) {
		return true;
	}
	return false;
}
