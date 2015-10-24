yextend
=======

Yara integrated software to handle archive file data.

yextend was written for the sake of augmenting yara. yara by itself is great but we realized that it could not natively handle archived content in the granular way that we needed it to. For instance, if we were hunting for malware and it happened to be buried a few levels into archived content, yara in its native form could not help us. So what we have done is natively handle the inflation of archived content. And we pass the inflated content of each discovered resource to yara so that it can work its magic natively on one file's payload. Then yara does what it does quite well in terms of pattern matching and such based on a given set of rules.


Notes:

- (10/24/2015) yextend version 1.3 will only work with yara 3.4.

	provided test rulesets (in the test_ruleset directory) follow this naming convention:
	- yara version number is now included in the compiled filename, example: "bayshore.yara.testing.ruleset.34.bin" is compiled with yarac 3.4
	- files with extension ".bin" (binary) are compiled
	- files without the ".bin" extension are clear text ruleset files
	- files with the string "meta" in them will include some rules with metadata in the "meta" section, example: "bayshore.yara.testing.meta.ruleset.34.bin"

	if your rules have data in the 'meta' section they will now show up in the output, take a look at 'RULEWITHMETA' below and you will see an example of such output

- (05/28/2015) yextend version 1.2 will only work with yara 3.3 and above

- This software was written and tested on Linux (both Fedora and Debian). Ports to other platforms are currently TBD.

- If a dir (and not a file) is passed in then this version will process all of the files at that top level. Subdirectories are not processed yet, that is coming as an enhancement.


Requirements to build and run:

- g++ (GNU c++ compiler)
- autoconf 2.69 or above
- openssl devel lib (sudo yum install openssl-devel or sudo apt-get install libssl-dev)
- zlib devel lib (sudo yum install zlib-devel or sudo apt-get install zlib1g-dev)
- libarchive (v4) be installed (sudo yum install libarchive-devel or sudo apt-get install libarchive-dev)
- pcrecpp (sudo yum install pcre-devel or sudo apt-get install libpcre3-dev)
- yara v3 be fully installed
- if you are running yara pre-version 3.1.X then yara v3 lib header files to be moved to a specific location after a typical yara install, steps:
	A. cd into the dir where you extracted yara (for this example I will use "/tmp/yara")
	B. sudo cp /tmp/yara/libyara/include/yara/* /usr/local/include/yara/


Instructions:

1 - Make sure all requirements set forth above are met

2 - Extract our software in the directory of your choice (referred to as THEDIR from now on)

	- cd THEDIR
	- tar -xvzf yextend.tar.gz

3 - Build:

	- ./autogen.sh
	
	- ./configure
	
	- make
		
4 - Test (optional)

	- LD_LIBRARY_PATH=/usr/local/lib ./yextend test_rulesets/bayshore.yara.testing.ruleset.34.bin test_files/
	- LD_LIBRARY_PATH=/usr/local/lib ./yextend test_rulesets/bayshore.yara.testing.meta.ruleset.34.bin test_files/

5 - Run:

	- prefix the run statement by telling LD_LIBRARY_PATH where the yara shared object lib (or its symlink) is. If you changed nothing during the yara install then that value is '/usr/local/lib'

	- the program 'yextend' takes in 2 arguments:

		1. A yara ruleset file
		2. A file name or a directory name where the target files exist
	
	example:
	
		- LD_LIBRARY_PATH=/usr/local/lib ./yextend ~/Desktop/bayshore.yara.rules /tmp/targetfiles/filex
		- LD_LIBRARY_PATH=/usr/local/lib ./yextend ~/Desktop/bayshore.yara.rules /tmp/targetfiles/
		
		***** 
			if you don't want to set LD_LIBRARY_PATH on each prog run then you can set it in your .bashrc (or equivalent on your system) as such:
		
			export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
			
			then the program runs would be as such:
	
				- ./yextend ~/Desktop/bayshore.yara.rules /tmp/targetfiles/filex
				- ./yextend ~/Desktop/bayshore.yara.rules /tmp/targetfiles/			
		*****

6 - Analyze output. The output will be structured as such (number of result stanzas will obviously vary based on the content at hand):
	
	===============================ALPHA===================================
	Filename: x
	File Size: y
	File Signature (MD5): z

	=======================================================================

	Yara Result(s): RULE1
	Scan Type: a
	Parent File Name: b
	Child File Name: c
	File Signature (MD5): d
	
	
	Yara Result(s): RULE2, RULEWITHMETA:[type=Simple string search,signature=Looking for 95,author=Dre,testint=9,d=false,hit_count=12], RULE3
	Scan Type: v
	Parent File Name: x
	Child File Name: y
	File Signature (MD5): z


	===============================OMEGA===================================
		
		
	A. example output from one of the test files:
	
		===============================ALPHA===================================
		Filename: test_files/rands_tarball.tar.gz
		File Size: 271386
		File Signature (MD5): 74edc10648f6d65e90cd859120eaa31b
		
		=======================================================================
		
		Yara Result(s): JUDO
		Scan Type: Yara Scan (ASCII Text File) inside GZIP Archive file
		Parent File Name: AAA.gz
		Child File Name: AAA
		File Signature (MD5): bf6aadaf4b6fb726040c1131d809bfc2
		
		
		Yara Result(s): EXE_DROP, MZ_PORTABLE_EXE, S95
		Scan Type: Yara Scan (Windows - Portable Executable) inside ZIP 2.0 (deflation) file
		Parent File Name: rand987.zip
		Child File Name: spoolsy.exe
		File Signature (MD5): 25ca7beed707e94ce70137f7d0c7b14e
		
		
		===============================OMEGA===================================
		
		
		This is based on file "test_files/rands_tarball.tar.gz" that has the following structure:
		
		rands_tarball.tar.gz
		|_ rands.tar
		   |_ rand123.zip
		      |_ AAA.gz
		         |_ AAA
		      rand987.zip
		      |_ spoolsy.exe


	B. another more complex example using one of the test files:


		===============================ALPHA===================================
		Filename: test_files/step1-zips.tar.gz
		File Size: 2400255
		File Signature (MD5): 98178b84fd9280fa1ed469c6512cd0ee

		=======================================================================

		Yara Result(s): EXE_DROP, MZ_PORTABLE_EXE, S95
		Scan Type: Yara Scan (Windows - Portable Executable) inside POSIX ustar format file
		Parent File Name: test_files/step1-zips.tar
		Child File Name: spoolsy.exe
		File Signature (MD5): 25ca7beed707e94ce70137f7d0c7b14e


		Yara Result(s): LOREM, S95
		Scan Type: Yara Scan (Office Open XML) inside ZIP 2.0 (deflation) file
		Parent File Name: Lorem-winlogon-spoolsy-pptx.docx
		Child File Name: word/document.xml
		File Signature (MD5): 9d58972d9a528da89c971597e4aa1844


		Yara Result(s): LOREM
		Scan Type: Yara Scan (Office Open XML) embedded in an Office Open XML file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slides/slide2.xml
		File Signature (MD5): 9c6bad391960e46aca89a6c7d6f0e40b


		Yara Result(s): EXE_DROP, S95
		Scan Type: Yara Scan (Microsoft Office document (DOC PPT XLS)) embedded in an Office Open XML file
		Parent File Name: Lorem-winlogon-spoolsy-pptx.docx
		Child File Name: word/embeddings/oleObject1.bin
		File Signature (MD5): 197c489374bb43831bd8b32cc22d414e


		Yara Result(s): EXE_DROP, S95
		Scan Type: Yara Scan (Microsoft Office document (DOC PPT XLS)) embedded in an Office Open XML file
		Parent File Name: Lorem-winlogon-spoolsy-pptx.docx
		Child File Name: word/embeddings/oleObject2.bin
		File Signature (MD5): 2b7ccfde542d23cf64e0533f467083e2


		Yara Result(s): LOREM, S95
		Scan Type: Yara Scan (Office Open XML) embedded in an Office Open XML file
		Parent File Name: xl/embeddings/Microsoft_Office_Word_Document1.docx
		Child File Name: word/document.xml
		File Signature (MD5): 9d58972d9a528da89c971597e4aa1844


		Yara Result(s): LOREM
		Scan Type: Yara Scan (Office Open XML) embedded in an Office Open XML file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slides/slide2.xml
		File Signature (MD5): 9c6bad391960e46aca89a6c7d6f0e40b


		Yara Result(s): EXE_DROP, S95
		Scan Type: Yara Scan (Microsoft Office document (DOC PPT XLS)) embedded in an Office Open XML file
		Parent File Name: xl/embeddings/Microsoft_Office_Word_Document1.docx
		Child File Name: word/embeddings/oleObject1.bin
		File Signature (MD5): 197c489374bb43831bd8b32cc22d414e


		Yara Result(s): EXE_DROP, S95
		Scan Type: Yara Scan (Microsoft Office document (DOC PPT XLS)) embedded in an Office Open XML file
		Parent File Name: xl/embeddings/Microsoft_Office_Word_Document1.docx
		Child File Name: word/embeddings/oleObject2.bin
		File Signature (MD5): 2b7ccfde542d23cf64e0533f467083e2


		Yara Result(s): LOREM
		Scan Type: Yara Scan (Office Open XML) inside ZIP 2.0 (deflation) file
		Parent File Name: Lorem-docx-embedded-step3.xlsx
		Child File Name: xl/sharedStrings.xml
		File Signature (MD5): 9183392950503e4b47edbc458c6126f5


		Yara Result(s): S95
		Scan Type: Yara Scan (Office Open XML) inside ZIP 2.0 (deflation) file
		Parent File Name: Lorem-docx-embedded-step3.xlsx
		Child File Name: xl/worksheets/sheet1.xml
		File Signature (MD5): 8bcbbe18c67ddadf35c2743b0435c16c


		===============================OMEGA===================================





		This is based on file "test_files/step1-zips.tar.gz" that has the following structure:
		
		step1-zips.tar.gz
		|_ docx-embedded-step3.xlsx.zip
		   |_ docx-embedded-step3.xlsx
		      |_ Lorem-winlogon-spoolsy-pptx.docx
		         |_ winlogon.exe
		         |_ spoolsy.exe
		         |_ pptx-plain.pptx
		|_ Lorem-winlogon-spoolsy-pptx.docx.zip
		   |_ Lorem-winlogon-spoolsy-pptx.docx
		      |_ winlogon.exe
		      |_ spoolsy.exe
		      |_ pptx-plain.pptx
		|_ spoolsy.exe


