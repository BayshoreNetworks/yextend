/*****************************************************************************
 *
 * YEXTEND: Help for YARA users.
 * Copyright (C) 2014 by Bayshore Networks, Inc. All Rights Reserved.
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

	FileDataPatterns["255044462d312e3"] = 2;
	FileDataPatternMap[2] = "Adobe PDF";
	FileDataPatternOffset[2] = 0;

	FileDataPatterns["504b030414000600080000002100"] = 3;
	FileDataPatternMap[3] = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)";
	FileDataPatternOffset[3] = 0;

	FileDataPatterns["d0cf11e0a1b11ae1"] = 4;
	FileDataPatternMap[4] = "Microsoft Office document (DOC PPT XLS)";
	FileDataPatternOffset[4] = 0;

	FileDataPatterns["d0cf11e0a1b11ae1000000000000000000000000000000003"] = 5;
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

    FileDataPatterns["504b0304"] = 15;
    FileDataPatternMap[15] = "Zip or Jar Archive";
    FileDataPatternOffset[15] = 0;

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
    
        
    
	/*
	 * default response ...
	 * meaning we did not detect a file type so
	 * we will treat this as a generic and
	 * unclassified binary file type
	 */
	FileDataPatterns["unclassified-binary"] = 65535;
	FileDataPatternMap[65535] = "Unclassified Binary";
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
	if ((ix == 47) || (ix == 48) || (ix == 49))
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
	if ((ix == 26) || (ix == 27) || (ix == 26000))
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
	// images are between 33 and 43 inclusive.
	return ((unsigned)ix - 33) < 11;
}

bool FileData::is_archive(int ix) {
	/*
     * 15 = zip
     * 17 = gzip
     * 18 = gzip
     * 46 = tar
     * is_rar() covers all known rar patterns
     */
    if ((ix == 15) ||
        (ix == 17) ||
        (ix == 18) ||
        (ix == 46) ||
        (is_rar(ix))
        )
        return true;
	return false;
}
