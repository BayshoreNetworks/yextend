#****************************************************************************
#
# YEXTEND: Help for YARA users.
# This file is part of yextend.
#
# Copyright (c) 2014-2018, Bayshore Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that
# the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#****************************************************************************/
import os
import json
from subprocess import Popen, PIPE

######################################################
LD_LIBRARY_PATH = 'LD_LIBRARY_PATH'
LIB_PATHS = "/usr/local/lib"
CMD = "./yextend"
CMD_JSON_OUT = "{} -r {} -t {} -j".format(CMD, "{}", "{}")

TARG_DIR = "test_files/"
YARA_RULES_ROOT = "test_rulesets/"

YARA_MATCHES_FOUND = "yara_matches_found"
RAW_DATA = "Raw data"
EXTRACTED_TEXT = "Extracted text"
SCAN_RESULTS = "scan_results"
SCAN_TYPE = "scan_type"
CHILD_FILE_NAME = "child_file_name"
WINDOWS_PORTABLE_EXE = "Windows Portable Executable"

#GUANGGAO_YARA_RULESET = "%sguanggao_rules.yara" % YARA_RULES_ROOT
LIPSUMPDF_YARA_RULESET = "%slorem_pdf.yara" % YARA_RULES_ROOT

#GUANGGAO_FILE = "guanggao.gif"
LIPSUM_PDF_FILE = "lipsum.txt.pdf"

LIPSUM_LOREM_YARA_RULE_ID = "LOREM_FILE_BODY"
LIPSUM_LOREM_YARA_RULE_VAR = "$lipsum_pdf_body_lorem"

GUANGGAO_YARA_RULESET = "%sguanggao_rules.yara" % YARA_RULES_ROOT
ZAP_PDF_YARA_RULESET = "%szap_pdf_rules.yara" % YARA_RULES_ROOT
MSOFFICE_YARA_RULESET = "%smsoffice_rules.yara" % YARA_RULES_ROOT
MSOFFICE_MACRO_YARA_RULESET = "%smsoffice_macro_rules.yara" % YARA_RULES_ROOT
MSOFFICEX_YARA_RULESET = "%smsofficex_rules.yara" % YARA_RULES_ROOT

BZ2_TEST_FILE = "test.txt.bz2"
GUANGGAO_FILE = "guanggao.gif"
GUANGGAO_CONTEXT_PATTERN1 = "guanggao_rule1"
GUANGGAO_CONTEXT_PATTERN2 = "guanggao_rule2"
GIF_IMAGE_RULE_ID = "GIF_IMAGE_FILE"
JAVASCRIPT_OPEN_TAG = "javascript_open_tag"
JAVASCRIPT_CLOSE_TAG = "javascript_close_tag"
IFRAME_OPEN_TAG = "iframe_open_tag"
IFRAME_CLOSE_TAG = "iframe_close_tag"

BZ2_PATTERN = "0x1b:$text"
ZAP_PDF_FILE = "ZAPGettingStartedGuide-2.4.pdf"
ZAP_PDF_FILE_GZIP = "ZAPGettingStartedGuide-2.4.pdf.gz"
ZAP_PDF_ZIP_FILE = "ZAPGettingStartedGuide-2.4.pdf.zip"
ZAP_PDF_ZIP_TARGZ_FILE = "ZAPGettingStartedGuide-2.4.pdf.zip.tar.gz"
ZAP_PDF_PATTERN = "0x1880:$fg"

MSOFFICE_DOC = "test_msoffice_word_doc.doc"
MSOFFICE_DOC_GZIP = "test_msoffice_word_doc.doc.gz"
MSOFFICE_DOC_GZIP_ZIP = "test_msoffice_word_doc.doc.gz.zip"
MSOFFICE_DOC_GZIP_ZIP_TARGZ = "test_msoffice_word_doc.doc.gz.zip.tar.gz"
MSOFFICE_BODY_FOOTER_PATTERN = "0x35f:$msoffice_doc_footer"
MSOFFICE_MACRO_PATTERN = "0x200a1:$obfuscation"

MSOFFICEX_DOC = "Lorem-winlogon.docx"
MSOFFICEX_DOC_TAR = "Lorem-winlogon.docx.tar"
MSOFFICEX_DOC_TAR_ZIP = "Lorem-winlogon.docx.tar.zip"
LOREM_BODY_PATTERN = "LOREM_FILE_BODY"
EXE_PATTERN = "EXE_DROP"

MSOFFICEX_DOC_EXE = "embedded-exe.docx"
ADOBE_PDF_PATTERN = "ADOBE_PDF"

CRYPTO_DOC_EXE = "Test.docx"
CRYPTO_YARA_RULESET = "%scrypto.yar" % YARA_RULES_ROOT
CRYPTO_PATTERN = "BLOWFISH_Constants"
CRYPTO_MD5_PATTERN = "MD5_Constants"
CRYPTO_RIPE_PATTERN = "RIPEMD160_Constants"

PACKER_EXE = "VirusShare_0059ec457f9f173260d2dcad8f1fbdf7"
PACKER_YARA_RULESET = "%spacker.yar" % YARA_RULES_ROOT
PACKER_PATTERN_1 = "offsets=0x10ce6:$a0"
PACKER_PATTERN_2 = "offsets=0x10ce6:$str1"

ZIP_7Z_FILE = "hmm.7z"

MZ_EXE = "VirusShare_007f9182c475c9a049020b7307ec6d35"
MZ_PATTERN = "MZ_PORTABLE_EXE"

JPG_TAR_DLL = "trick.jpg"

MULTIPLE_EMBED_PDF = "pdf_with_multiple_embedded.pdf"
MULTIPLE_EMBED_PDF_RULESET = "{}{}".format(YARA_RULES_ROOT, "pdf_multiple_embed.yara")

######################################################

class Test_Yextend_files():

    '''
        GIF file with embedded javascript
    '''
    def test_yara_guanggao_gif(self):
        f_obj = TARG_DIR + GUANGGAO_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", GUANGGAO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert("0x0:$gif_image_file" in out and "0x6a96:$scriptbin" in out and "0x69f9:$iframebin" in out)


    '''
        simple PDF
    '''
    def test_lipsum_pdf(self):
        f_obj = TARG_DIR + LIPSUM_PDF_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", LIPSUMPDF_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LIPSUM_PDF_FILE in out and LIPSUM_LOREM_YARA_RULE_ID in out and out.count(LIPSUM_LOREM_YARA_RULE_VAR) > 1)


    def test_content_yara_zap_pdf(self):
        f_obj = TARG_DIR + ZAP_PDF_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(ZAP_PDF_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    for jj in jresp[SCAN_RESULTS]:
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)
            #assert(ZAP_PDF_PATTERN in out)


    def test_content_yara_zap_pdf_gzip(self):
        f_obj = TARG_DIR + ZAP_PDF_FILE_GZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(ZAP_PDF_YARA_RULESET, f_obj)
            #proc = Popen([CMD, "-r", ZAP_PDF_YARA_RULESET, "-t", f_obj],
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    for jj in jresp[SCAN_RESULTS]:
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)
            #assert(ZAP_PDF_PATTERN in out)


    def test_content_yara_zap_pdf_zip(self):
        f_obj = TARG_DIR + ZAP_PDF_ZIP_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(ZAP_PDF_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    for jj in jresp[SCAN_RESULTS]:
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)
            #assert(ZAP_PDF_PATTERN in out)
            #print out


    def test_content_yara_zap_pdf_zip_targz(self):
        f_obj = TARG_DIR + ZAP_PDF_ZIP_TARGZ_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(ZAP_PDF_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    for jj in jresp[SCAN_RESULTS]:
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    def test_content_yara_msoffice_doc_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICE_MACRO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(MSOFFICE_MACRO_PATTERN in out)


    def test_content_yara_msoffice_doc_gzip_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC_GZIP
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICE_MACRO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(MSOFFICE_MACRO_PATTERN in out)



    def test_content_yara_msoffice_doc_gzip_zip_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC_GZIP_ZIP
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICE_MACRO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(MSOFFICE_MACRO_PATTERN in out)



    def test_content_yara_msoffice_doc_gzip_zip_targz_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC_GZIP_ZIP_TARGZ
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICE_MACRO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(MSOFFICE_MACRO_PATTERN in out)


    def test_content_yara_msofficex_doc(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LOREM_BODY_PATTERN in out)
            assert(EXE_PATTERN in out)


    def test_content_yara_msofficex_doc_tar(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_TAR
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LOREM_BODY_PATTERN in out)
            assert(EXE_PATTERN in out)


    def test_content_yara_msofficex_doc_tar_zip(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_TAR_ZIP
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LOREM_BODY_PATTERN in out)
            assert(EXE_PATTERN in out)


    '''
        word (.docx) file with header, footer,
        embedded pdf and 2 embedded windows executables (.exe)
    '''
    def test_content_yara_msofficex_doc_exe(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_EXE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LOREM_BODY_PATTERN in out)
            assert(EXE_PATTERN in out)
            assert(ADOBE_PDF_PATTERN in out)
            assert(out.count(EXE_PATTERN) == 2)


    def test_content_yara_crypto_doc_exe(self):
        f_obj = TARG_DIR + CRYPTO_DOC_EXE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", CRYPTO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(CRYPTO_PATTERN in out)
            assert(CRYPTO_MD5_PATTERN in out)
            assert(CRYPTO_RIPE_PATTERN in out)



    def test_content_yara_packer_exe(self):
        f_obj = TARG_DIR + PACKER_EXE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", PACKER_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(PACKER_PATTERN_1 in out)
            assert(PACKER_PATTERN_2 in out)


    def test_content_yara_7z(self):
        f_obj = TARG_DIR + ZIP_7Z_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LOREM_BODY_PATTERN in out)
            assert(EXE_PATTERN in out)



    def test_content_yara_msofficex_exe(self):
        f_obj = TARG_DIR + MZ_EXE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(MZ_PATTERN in out)


    def test_content_yara_jpg_tar_dll(self):
        f_obj = TARG_DIR + JPG_TAR_DLL
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MSOFFICEX_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(LOREM_BODY_PATTERN in out)
            assert(EXE_PATTERN in out)

    def test_yara_random_bz2(self):
        f_obj = TARG_DIR + BZ2_TEST_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", GUANGGAO_YARA_RULESET, "-t", f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            assert(BZ2_PATTERN in out)

    def test_yara_multiple_embedded_pdf(self):
        f_obj = TARG_DIR + MULTIPLE_EMBED_PDF
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MULTIPLE_EMBED_PDF_RULESET, "-t", f_obj, "-j"],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            #print out
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    for jj in jresp[SCAN_RESULTS]:
                        #print jj
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE] and CHILD_FILE_NAME in jj:
                            if jj[CHILD_FILE_NAME] == "bj.exe":
                                assert(jj[YARA_MATCHES_FOUND] == True)
