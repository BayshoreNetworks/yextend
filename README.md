ywrapper
========

Yara integrated software to handle archive file data.

ywrapper was written for the sake of augmenting yara. yara by itself is great but we realized that it could not natively handle archived content in the granular way that we needed it to.
For instance, if we were hunting for malware and it happened to be buried a few levels into archived content, yara in its native form could not help us. So what we have done is natively handle the
deflation of archived content. And we pass the inflated content of each discovered file to yara so that it sees what it is looking for, one file's payload, and then does what it does quite well in terms
or pattern matching based on a given set of rules.


Notes:

- This software was written for yara v3 so make sure you are on v3 if you want to use this.

- This software was written and tested on Linux (both Fedora and Debian) and there are currently zero plans to port this over to windows, Mac OSX maybe. But we dont even own windows machines ...

- If a dir (and not a file) is passed in then this version will process all of the files at that top level. Subdirectories are not processed yet, that is coming as an enhancement.


Requirements to build and run:

- openssl devel lib (sudo apt-get install libssl-dev or sudo yum install openssl-devel)
- zlib devel lib
- libarchive (v4) be installed (sudo yum install libarchive-devel or sudo apt-get install libarchive-dev)
- yara v3 be fully installed
- yara v3 lib header files to be moved to a specific location after a typical yara install, steps:
	A. cd into the dir where you extracted yara (for this example I will use "/tmp/yara")
	B. sudo cp /tmp/yara/libyara/include/yara/* /usr/local/include/yara/


Instructions:

1. Make sure all requirements set forth above are met

2. Extract our software in the directory of your choice (referred to as THEDIR from now on)

	- cd THEDIR
	- tar -xvzf ywrapper.tar.gz

3. Build:

	- ./autogen.sh
	
	- ./configure
	
	- make
		
4. Test (optional)

	- LD_LIBRARY_PATH=/usr/local/lib ./ywrapper test_rulesets/bayshore.yara.testing.ruleset.bin test_files/

5. Run:

	- prefix the run statement by telling LD_LIBRARY_PATH where the yara shared object lib (or its symlink) is. If you changed nothing during the yara install then that value is '/usr/local/lib'
	- the program 'ywrapper' takes in 2 arguments:
		1. A yara ruleset file
		2. A file name or a directory name where the target files exist
	
	example:
	
		- LD_LIBRARY_PATH=/usr/local/lib ./ywrapper ~/Desktop/bayshore.yara.rules /tmp/targetfiles/filex
		- LD_LIBRARY_PATH=/usr/local/lib ./ywrapper ~/Desktop/bayshore.yara.rules /tmp/targetfiles/
		
		*** 
			if you don't want to set LD_LIBRARY_PATH on each prog run then you can set it in your .bashrc (or equivalent on your system) as such:
		
			export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
			
			then the program runs would be as such:
	
				- LD_LIBRARY_PATH=/usr/local/lib ./ywrapper ~/Desktop/bayshore.yara.rules /tmp/targetfiles/filex
				- LD_LIBRARY_PATH=/usr/local/lib ./ywrapper ~/Desktop/bayshore.yara.rules /tmp/targetfiles/			
		***
		
		
	output will be structured as such (number of result stanzas will obviously vary based on the content at hand):
	
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
		
		
		Yara Result(s): RULE2, RULE3
		Scan Type: v
		Parent File Name: x
		Child File Name: y
		File Signature (MD5): z


		===============================OMEGA===================================
		
		
	example output from one of the test files:
	
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
		
