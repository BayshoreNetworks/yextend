yextend
=======

<p>
<a href="https://scan.coverity.com/projects/bayshorenetworks-yextend">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/13906/badge.svg"/>
</a>
<a href="https://www.openhub.net/p/yextend?ref=Thin+badge" rel="nofollow"><img alt="OpenHub-Status" src="https://www.openhub.net/p/yextend/widgets/project_thin_badge?format=gif" data-canonical-src="https://www.openhub.net/p/yextend/widgets/project_thin_badge?format=gif" style="max-width:100%;"></a>
</p>


Yara integrated software to handle archive file data.

yextend was written for the sake of augmenting yara. yara by itself is great but we realized that it could not natively handle archived content in the granular way that we needed it to. For instance, if we were hunting for malware and it happened to be buried a few levels into archived content, yara in its native form could not help us. So what we have done is natively handle the inflation of archived content. And we pass the inflated content of each discovered resource to yara so that it can work its magic natively on one file's payload. Then yara does what it does quite well in terms of pattern matching and such based on a given set of rules.


Software Credits

	- Yara is originally authored by Victor M. Alvarez (https://github.com/VirusTotal/yara) - License: https://raw.githubusercontent.com/VirusTotal/yara/master/COPYING
	- json.hpp is authored by Niels Lohmann (https://github.com/nlohmann/json) - License: https://raw.githubusercontent.com/nlohmann/json/develop/LICENSE.MIT  *** Note that for Yextend to compile I had to make a change to the original json.hpp - function "get_string" was causing name conflicts with function "get_string" from Yara. So I renamed json.hpp's function to "j_get_string"


Notes:

- (12/08/2017) yextend version 1.6

	- added support for bzip2
	- added numerous new file type detection patterns
	- added macro file detection inside of .docm files
	- added support for JSON output (standard and advanced)

- (08/30/2016) yextend version 1.5

	- native parsing for PDF documents such that the Yara rulesets are now running against:
		- the target PDF's binary data set
		- the raw text (extracted out of the binary data set) from the target PDF
	- file type detection has been re-written so that it is now performed against a Yara ruleset
	- added some initial debug code (based on bool flag)
	- more test files added
	- nose based unit tests added
	- yextend is now licensed via the BSD (3-clause) license

- (03/18/2016) yextend version 1.4 - output enhancements and runtime helper prog

	- output now includes the offset and string definition identifier for every hit reported by Yara
	- output now includes the name of the Yara ruleset file at hand
	- initial release of run_yextend prog

- (10/24/2015) yextend version 1.3 will only work with yara 3.4.

	- if your rules have data in the 'meta' section they will now show up in the output, take a look at 'RULEWITHMETA' below and you will see an example of such output

- (05/28/2015) yextend version 1.2 will only work with yara 3.3 and above

- This software was written and tested on Linux (both Fedora and Debian). Ports to other platforms are currently TBD.

- If a dir (and not a file) is passed in then this version will process all of the files at that top level. Subdirectories are not processed yet.



Requirements to build and run:

- g++ (GNU c++ compiler - c++11)
- autoconf 2.69 or above
- openssl devel lib (sudo dnf install openssl-devel or sudo apt-get install libssl-dev)
- zlib devel lib (sudo dnf install zlib-devel or sudo apt-get install zlib1g-dev)
- bzlib devel lib (sudo dnf install bzip2-devel or sudo apt-get install libbz2-dev)
- libarchive (v4) be installed (sudo dnf install libarchive-devel or sudo apt-get install libarchive-dev)
- pcrecpp (sudo dnf install pcre-devel or sudo apt-get install libpcre3-dev)
- uuid (sudo dnf install uuid-devel / libuuid-devel or sudo apt-get install uuid-dev)
- nose (sudo dnf install python2-nose or sudo apt-get install python-nose)
- yara v3.X be fully installed
- if you are running yara pre-version 3.1.X then yara v3 lib header files to be moved to a specific location after a typical yara install, steps:
	A. cd into the dir where you extracted yara (for this example I will use "/tmp/yara")
	B. sudo cp /tmp/yara/libyara/include/yara/* /usr/local/include/yara/



Instructions:

1 - Make sure all requirements set forth above are met

2 - Extract our software in the directory of your choice (referred to as THEDIR from now on)

	- cd THEDIR
	- tar -xvzf yextend.tar.gz

3 - Build (make sure the executable bit is set on the file system for build.sh):

	- ./build.sh

4 - Test (optional)

	- make unittests

5 - Run:

	- Note on run modes:

		- No arguments/switches passed in means the output is intended for human eyes
		- The -j switch means the output is for machine to consume [JSON]
		- The -a switch, used in conjunction -j, means that file structure/hierarchy will be added to the machine consumable JSON output

	- 2 options to run:

	A. use executable run_yextend - it wraps the native yextend executable. To run:

	- the program 'run_yextend' takes in 2 mandatory arguments, 1 optional:

		1. A yara ruleset file or directory of ruleset files
		2. A file name or a directory of target files
		3. '-j' for json output [optional]

	usage:
        -r or --ruleset             rule_entity
        -t or --target              target_file_entity
        -j

        examples:
		 ./run_yextend -r rule_entity -t target_file_entity
        ./run_yextend --ruleset rule_entity -t target_file_entity
        ./run_yextend -r rule_entity -t target_file_entity -j

		***** make sure the executable bit is set on the file system for run_yextend *****

	B. run yextend executable - prefix the run statement by telling LD_LIBRARY_PATH where the yara shared object lib (or its symlink) is. If you changed nothing during the yara install then that value is '/usr/local/lib'

	- the program 'yextend' takes in 2 mandatory arguments, 1 optional:

		1. A yara ruleset file
		2. A file name or a directory name where the target files exist
		3. '-j' for json output [optional]

	usage:
        -r rule_entity
        -t target_file_entity
        -j

	example:

		- LD_LIBRARY_PATH=/usr/local/lib ./yextend -r ~/Desktop/bayshore.yara.rules -t /tmp/targetfiles/filex
		- LD_LIBRARY_PATH=/usr/local/lib ./yextend -r ~/Desktop/bayshore.yara.rules -t /tmp/targetfiles/
		- LD_LIBRARY_PATH=/usr/local/lib ./yextend -r ~/Desktop/bayshore.yara.rules -t /tmp/targetfiles/filex -j

		*****
			if you don't want to set LD_LIBRARY_PATH on each prog run then you can set it in your .bashrc (or equivalent on your system) as such:

			export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

			then the program runs would be as such:

				- ./yextend -r ~/Desktop/bayshore.yara.rules -t /tmp/targetfiles/filex
				- ./yextend -r ~/Desktop/bayshore.yara.rules -t /tmp/targetfiles/			
		*****

6 - Analyze output. The output will be structured as such (number of result stanzas will obviously vary based on the content at hand):

	===============================ALPHA===================================
	Ruleset File Name: w
	File Name: x
	File Size: y
	File Signature (MD5): z

	=======================================================================

	Yara Result(s): RULE1:[detected offsets=0x48:$a,hit_count=1]
	Scan Type: a
	Parent File Name: b
	Child File Name: c
	File Signature (MD5): d


	Yara Result(s): RULE2, RULEWITHMETA:[type=Simple string search,signature=Looking for 95,author=Dre,testint=9,d=false,detected offsets=0x0:$a-0x1:$a-0x2:$a-0x3:$a,hit_count=4], RULE3
	Scan Type: v
	Parent File Name: x
	Child File Name: y
	File Signature (MD5): z


	===============================OMEGA===================================

	For each result stanza you will be presented with a listing of the relevant Yara rules that hit. This will be in the key/value pair with key "Yara Result(s)". The value here is formatted as follows:

		RULE_ID:[META_DATA,OFFSETS,HIT_COUNT], RULE_ID[OFFSETS,HIT_COUNT], ... RULE_ID[OFFSETS,HIT_COUNT]

		Inside the square brackets:

			The "META_DATA" are comma-separated and represent the data from your rules "meta" section. As this is optional you may see no meta-data output from yextend.
			The OFFSETS are comma-separated. Each offset listing is delimited by a dash and represent the offset in the content where the rule hit took place and the respective string definition identifier from your Yara rule.
			The HIT_COUNT is simply a listing of the number of rule hits.

		Here is an example:

			EXE_DROP:[detected offsets=0x4e:$a,hit_count=1], MZ_PORTABLE_EXE, S95:[detected offsets=0xd94e:$a-0x2c5b5:$b,hit_count=2]

		Breakdown: In this example there are 3 rules that hit:

			RULE_ID: EXE_DROP
			META_DATA: No meta data listed as there is none in the rule
			OFFSETS: detected offsets=0x4e:$a ("0x4e" is the offset in the content and "$a" is the respective string definition identifier)
			HIT_COUNT: hit_count=1

			RULE_ID: MZ_PORTABLE_EXE (Nothing else is listed because this rule only has the required "condition" section)

			RULE_ID: S95
			META_DATA: No meta data listed as there is none in the rule
			OFFSETS: detected offsets=0xd94e:$a-0x2c5b5:$b ("0xd94e" is one offset in the content that hit on string definition "$a". "0x2c5b5" is another offset in the content that hit on string definition "$b")
			HIT_COUNT: hit_count=2



	A. example output from one of the test files:

		===============================ALPHA===================================
		Ruleset File Name: test_rules/ruleset_blah
		File Name: test_files/rands_tarball.tar.gz
		File Size: 271386
		File Signature (MD5): 74edc10648f6d65e90cd859120eaa31b

		=======================================================================

		Yara Result(s): JUDO:[detected offsets=0x48:$a,hit_count=1]
		Scan Type: Yara Scan (ASCII Text File) inside GZIP Archive file
		Parent File Name: AAA.gz
		Child File Name: AAA
		File Signature (MD5): bf6aadaf4b6fb726040c1131d809bfc2


		Yara Result(s): EXE_DROP:[detected offsets=0x4e:$a,hit_count=1], MZ_PORTABLE_EXE, S95:[detected offsets=0xd94e:$a-0x2c5b5:$a,hit_count=2]
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
		Ruleset File Name: test_rules/ruleset_blah
		File Name: test_files/step1-zips.tar.gz
		File Size: 2400255
		File Signature (MD5): 98178b84fd9280fa1ed469c6512cd0ee

		=======================================================================

		Yara Result(s): EXE_DROP:[type=EXE DROP detection,signature=Some test sig,uuid=ce354f47467b31e4addcf4b7e2c79a19,detected offsets=0x4e:$a,hit_count=1], MZ_PORTABLE_EXE, S95:[type=Simple string search,signature=Looking for 95,author=Dre,detected offsets=0xd94e:$a-0x2c5b5:$a,hit_count=2]
		Scan Type: Yara Scan (Windows - Portable Executable) inside POSIX ustar format file
		Parent File Name: test_files/step1-zips.tar
		Child File Name: spoolsy.exe
		File Signature (MD5): 25ca7beed707e94ce70137f7d0c7b14e


		Yara Result(s): CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x40:$a-0x5a:$a-0xbf:$a-0x154:$a-0x175:$a-0x18f:$a-0x1ad:$a-0x1d6:$a-0x1fc:$a-0x235:$a-0x25c:$a-0x282:$a-0x2b4:$a-0x2dc:$a-0x302:$a-0x330:$a-0x359:$a-0x37f:$a-0x3b3:$a-0x3f4:$a-0x453:$a-0x479:$a-0x499:$a-0x4c3:$a-0x4e9:$a-0x51e:$a-0x54a:$a-0x570:$a-0x5a7:$a-0x5d0:$a-0x5f6:$a-0x619:$a,hit_count=33]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: Lorem-winlogon-spoolsy-pptx.docx
		Child File Name: [Content_Types].xml
		File Signature (MD5): 64a53ef2e6b1b9ed389232cc69898289

		Yara Result(s): S95:[type=Simple string search,signature=Looking for 95,author=Dre,detected offsets=0x2ee:$a-0x1698:$a,hit_count=2], CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x42:$a-0x5e:$a-0x1980:$a-0x19c4:$a,hit_count=5]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: Lorem-winlogon-spoolsy-pptx.docx
		Child File Name: word/theme/theme1.xml
		File Signature (MD5): 3badbd456f490c89a3a9a118c0eb9aca

		...

		Yara Result(s): CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x49:$a-0x65:$a-0x89:$a-0xa5:$a-0xd7:$a-0xf3:$a-0xd0d:$a-0xd16:$a,hit_count=9]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/presentation.xml
		File Signature (MD5): c312ab4768729234a74c94a67ccce68d


		Yara Result(s): LOREM:[detected offsets=0x31b:$a-0x4881:$a,hit_count=2], CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x40:$a-0x5c:$a-0x80:$a-0x9c:$a-0xce:$a-0xea:$a-0x5d07:$a-0x5d10:$a,hit_count=9]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slides/slide2.xml
		File Signature (MD5): f8625ea3f7e5c1e10ca78b9dc72ebcf5


		Yara Result(s): CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x40:$a-0x5c:$a-0x80:$a-0x9c:$a-0xce:$a-0xea:$a-0x587:$a-0x590:$a,hit_count=9]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slides/slide3.xml
		File Signature (MD5): 0bd56ae94bb2d043477c4d2189c44723


		Yara Result(s): CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x40:$a-0x5c:$a-0x80:$a-0x9c:$a-0xce:$a-0xea:$a-0x587:$a-0x590:$a,hit_count=9]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slides/slide1.xml
		File Signature (MD5): 01b2314a10da34be2161e2057198e5ef

		...

		Yara Result(s): S95:[type=Simple string search,signature=Looking for 95,author=Dre,detected offsets=0xa48:$a-0xd21:$a,hit_count=2], CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x46:$a-0x62:$a-0x86:$a-0xa2:$a-0xd4:$a-0xf0:$a-0x349:$a-0x352:$a,hit_count=9]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slideLayouts/slideLayout16.xml
		File Signature (MD5): 51f0848ae9a1c864fe467bddac461cde


		Yara Result(s): S95:[type=Simple string search,signature=Looking for 95,author=Dre,detected offsets=0x6c0:$a-0x999:$a,hit_count=2], CTXTESTXML:[type=nocase 'XML' search,signature=Some test XML sig,testint=9,d=false,detected offsets=0x2:$a-0x46:$a-0x62:$a-0x86:$a-0xa2:$a-0xd4:$a-0xf0:$a-0x33f:$a-0x348:$a,hit_count=9]
		Scan Type: Yara Scan (XML Document) inside ZIP 2.0 (deflation) file
		Parent File Name: word/embeddings/Microsoft_Office_PowerPoint_Presentation1.pptx
		Child File Name: ppt/slideLayouts/slideLayout6.xml
		File Signature (MD5): eefa70fd1d867683d9a4ad3e36b4b9fa


		===============================OMEGA===================================


		This last example is based on file "test_files/step1-zips.tar.gz" that has the following structure:

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


	C. An example of standard JSON output:

		./run_yextend -r test_rulesets/BAYSHORE_Officex1.yar -t test_files/Lorem-winlogon.docx.bz2 -j
		[
    		{
        		"file_name": "test_files/Lorem-winlogon.docx.bz2",
        		"file_signature_MD5": "26b485701d6a47618a7f915aa7a38045",
        		"file_size": 208940,
        		"scan_results": [
            		{
                		"child_file_name": "word/document.xml",
                		"file_signature_MD5": "9d58972d9a528da89c971597e4aa1844",
                		"parent_file_name": "test_files/Lorem-winlogon.docx",
                		"scan_type": "Yara Scan (Office Open XML)  inside BZIP2 Archive file",
                		"yara_matches_found": false
            		},
            		{
                		"child_file_name": "word/embeddings/oleObject1.bin",
                		"description": "suspicious marco action",
                		"detected offsets": [
                    		"0x12231:$a02",
                    		"0x135c5:$a03",
                    		"0x55dc7:$a03",
                    		"0x5f1e2:$a03",
                    		"0x55db9:$a09",
                    		"0x5f1d5:$a09",
                    		"0x55e31:$a12",
                    		"0x1037d:$a15"
                		],
                		"file_signature_MD5": "27250593fccbfb679320a74be9459d17",
                		"hit_count": "8",
                		"parent_file_name": "test_files/Lorem-winlogon.docx",
                		"scan_type": "Yara Scan (Microsoft Office document (DOC PPT XLS)) embedded in an Office Open XML file",
                		"yara_matches_found": true,
                		"yara_rule_id": "maldoc_suspicious_strings"
            		},
            		{
                		"child_file_name": "word/embeddings/oleObject1.bin",
                		"file_signature_MD5": "6674f1535a94304e58f26d06f348190d",
                		"parent_file_name": "test_files/Lorem-winlogon.docx",
                		"scan_type": "Yara Scan (Office Open XML)  inside BZIP2 Archive file",
                		"yara_matches_found": false
            		}
        		],
        		"yara_matches_found": true,
        		"yara_ruleset_file_name": "test_rulesets/BAYSHORE_Officex1.yar"
    		}
		]


	D. An example of advanced JSON output:

             ./run_yextend -r test_rulesets/BAYSHORE_Officex1.yar -t test_files/Lorem-winlogon.docx.bz2 -j -a
             [
                 {
                     "yara_matches_found": true,
                     "scan_results": [
                         {
                             "yara_matches_found": false,
                             "file_name": "test_files/Lorem-winlogon.docx",
                             "file_size": 210193,
                             "children": [
                                 {
                                     "yara_matches_found": false,
                                     "file_size": 29639,
                                     "file_name": "word/document.xml",
                                     "file_signature_MD5": "9d58972d9a528da89c971597e4aa1844",
                                     "scan_type": "Yara Scan (Office Open XML)  inside BZIP2 Archive file"
                                 },
                                 {
                        	     "yara_matches_found": true,
                                     "file_name": "word/embeddings/oleObject1.bin",
                        	     "scan_type": "Yara Scan (Microsoft Office document (DOC PPT XLS)) embedded in an Office Open XML file",
                                     "yara_results": {
                                         "maldoc_suspicious_strings": {
                                             "description": "suspicious marco action",
                                             "hit_count": "8",
                                             "offsets": [
                                                "0x12231:$a02",
                                                "0x135c5:$a03",
                                                "0x55dc7:$a03",
                                                "0x5f1e2:$a03",
                                                "0x55db9:$a09",
                                                "0x5f1d5:$a09",
                                                "0x55e31:$a12",
                                                "0x1037d:$a15"
                                             ]
                                         }
                                     },
                                     "file_size": 392192,
                                     "file_signature_MD5": "27250593fccbfb679320a74be9459d17"
                                 },
                                 {
                                     "yara_matches_found": false,
                                     "file_size": 8,
                                     "file_name": "word/embeddings/oleObject1.bin",
                                     "file_signature_MD5": "6674f1535a94304e58f26d06f348190d",
                                     "scan_type": "Yara Scan (Office Open XML)  inside BZIP2 Archive file"
                                 }
                             ],
                             "file_signature_MD5": "d8f0fab30eae91687c0d80f8dd08218f"
                         }
                     ],
       	             "file_name": "test_files/Lorem-winlogon.docx.bz2",
       	             "yara_ruleset_file_name": "test_rulesets/BAYSHORE_Officex1.yar",
       	             "file_size": 208940,
       	             "children": [
                        {
               	            "yara_matches_found": false,
               	            "file_size": 210193,
                            "file_name": "test_files/Lorem-winlogon.docx",
                            "file_signature_MD5": "d8f0fab30eae91687c0d80f8dd08218f"
                        }
                    ],
                    "file_signature_MD5": "26b485701d6a47618a7f915aa7a38045"
                }
            ]
