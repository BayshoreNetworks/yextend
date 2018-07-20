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

#****************************************************************************
# Test                                                      File                            Ruleset
#
# test_yara_guanggao_gif                                    GUANGGAO_GIF_FILE               GUANGGAO_YARA_RULESET
# test_yara_guanggao_gif_bz2                                GUANGGAO_GIF_BZ2_FILE           GUANGGAO_YARA_RULESET
# test_yara_guanggao_gif2                                   GUANGGAO_GIF_FILE2              GUANGGAO_YARA_RULESET
# test_lipsum_pdf                                           LIPSUM_PDF_FILE                 LIPSUMPDF_YARA_RULESET
# test_lipsum_pdf_zip                                       CRYPTO_LIPSUM_ZIP               LIPSUMPDF_YARA_RULESET
# test_content_yara_zap_pdf                                 ZAP_PDF_FILE                    ZAP_PDF_YARA_RULESET
# test_content_yara_zap_pdf_tar                             ZAP_PDF_TAR_FILE                ZAP_PDF_YARA_RULESET
# test_content_yara_zap_pdf_gzip                            ZAP_PDF_GZIP_FILE               ZAP_PDF_YARA_RULESET
# test_content_yara_zap_pdf_zip                             ZAP_PDF_ZIP_FILE                ZAP_PDF_YARA_RULESET
# test_content_yara_zap_pdf_zip_targz                       ZAP_PDF_ZIP_TARGZ_FILE          ZAP_PDF_YARA_RULESET
# test_content_yara_msoffice_doc_macro                      MSOFFICE_DOC                    MSOFFICE_MACRO_YARA_RULESET
# test_content_yara_msoffice_doc_gzip_macro                 MSOFFICE_DOC_GZIP               MSOFFICE_MACRO_YARA_RULESET
# test_content_yara_msoffice_doc_gzip_zip_macro             MSOFFICE_DOC_GZIP_ZIP           MSOFFICE_MACRO_YARA_RULESET
# test_content_yara_msoffice_doc_gzip_zip_targz_macro       MSOFFICE_DOC_GZIP_ZIP_TARGZ     MSOFFICE_MACRO_YARA_RULESET
# test_content_yara_msofficex_doc                           MSOFFICEX_DOC                   MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_tar                       MSOFFICEX_DOC_TAR               MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_tar_zip                   MSOFFICEX_DOC_TAR_ZIP           MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_zip                       MSOFFICEX_DOC_ZIP               MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_bz2                       MSOFFICEX_DOC_BZ2               MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_gz                        MSOFFICEX_DOC_GZ                MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_gz_zip                    MSOFFICEX_DOC_GZ_ZIP            MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_gz_zip_tar_gz             MSOFFICEX_DOC_GZ_ZIP_TAR_GZ     MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_gz_zip_tar_gz_bz2         MSOFFICEX_DOC_GZ_ZIP_TAR_GZ_BZ2 MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_doc_exe                       MSOFFICEX_DOC_EXE               MSOFFICEX_YARA_RULESET
# test_content_yara_crypto_doc_exe                          CRYPTO_DOC_EXE                  CRYPTO_YARA_RULESET
# test_content_yara_crypto_docm                             CRYPTO_DOCM                     CRYPTO_YARA_RULESET
# test_content_yara_crypto_7z                               CRYPTO_7Z                       CRYPTO_YARA_RULESET
# test_content_yara_crypto_zip                              CRYPTO_LIPSUM_ZIP               CRYPTO_YARA_RULESET
# test_content_yara_crypto_doc_bz2                          CRYPTO_DOC_BZ2                  CRYPTO_YARA_RULESET
# test_content_yara_packer_exe                              PACKER_EXE                      PACKER_YARA_RULESET
# test_content_yara_packer_exe2                             PACKER_EXE                      PACKER_YARA_RULESET
# test_content_yara_packer_exe3                             PACKER_EXE                      PACKER_YARA_RULESET
# test_content_yara_7z                                      ZIP_7Z_FILE                     MSOFFICEX_YARA_RULESET
# test_content_yara_msofficex_exe                           MZ_EXE                          MSOFFICEX_YARA_RULESET
# test_content_yara_dll                                     MZ_DLL                          MSOFFICEX_YARA_RULESET
# test_content_yara_jpg_tar_dll                             JPG_TAR_DLL                     MSOFFICEX_YARA_RULESET
# test_yara_random_txt                                      TXT_FILE                        GUANGGAO_YARA_RULESET
# test_yara_random_bz2                                      BZ2_FILE                        GUANGGAO_YARA_RULESET
# test_yara_multiple_embedded_pdf                           MULTIPLE_EMBED_PDF              MULTIPLE_EMBED_PDF_RULESET
# test_yara_archive_rar_lipsum                              ARCHIVE_RAR                     LIPSUMPDF_YARA_RULESET
# test_yara_archive_rar_msofficex                           ARCHIVE_RAR                     MSOFFICEX_YARA_RULESET
# test_yara_archive_rar_packer                              ARCHIVE_RAR                     PACKER_YARA_RULESET
# test_yara_archive_rar_multiple_embed_pdf                  ARCHIVE_RAR                     MULTIPLE_EMBED_PDF_RULESET
# test_content_yara_7z_lipsum                               ZIP_7Z_FILE                     LIPSUMPDF_YARA_RULESET
# test_content_yara_7z_guanggao                             ZIP_7Z_FILE                     GUANGGAO_YARA_RULESET
# test_content_yara_7z_crypto                               ZIP_7Z_FILE                     CRYPTO_YARA_RULESET
# test_content_yara_7z_multiple_embed_pdf                   ZIP_7Z_FILE                     MULTIPLE_EMBED_PDF_RULESET
# test_content_yara_so_guanggao                             SO_FILE                         GUANGGAO_YARA_RULESET
# test_content_yara_so_msoffice                             SO_FILE                         MSOFFICE_YARA_RULESET
# test_content_yara_so_crypto                               SO_FILE                         CRYPTO_YARA_RULESET
# test_content_yara_putty_guanggao                          PUTTY_EXE                       GUANGGAO_YARA_RULESET
# test_content_yara_putty_msofficex                         PUTTY_EXE                       MSOFFICEX_YARA_RULESET
# test_content_yara_putty_crypto                            PUTTY_EXE                       CRYPTO_YARA_RULESET
# test_content_yara_putty_multiple_embed_pdf                PUTTY_EXE                       MULTIPLE_EMBED_PDF_RULESET
# test_content_yara_putty_zip_guanggao                      PUTTY_EXE_ZIP                   GUANGGAO_YARA_RULESET
# test_content_yara_putty_zip_msofficex                     PUTTY_EXE_ZIP                   MSOFFICEX_YARA_RULESET
# test_content_yara_putty_zip_crypto                        PUTTY_EXE_ZIP                   CRYPTO_YARA_RULESET
# test_content_yara_putty_zip_multiple_embed_pdf            PUTTY_EXE_ZIP                   MULTIPLE_EMBED_PDF_RULESET
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
DETECTED_OFFSETS = "detected offsets"
SCAN_RESULTS = "scan_results"
SCAN_TYPE = "scan_type"
CHILD_FILE_NAME = "child_file_name"
YARA_RULE_ID = "yara_rule_id"
SEARCH_RANDOM_TEXT = "search_random_text"
RAW_DATA = "Raw data"
EXTRACTED_TEXT = "Extracted text"
IMAGE_FILE = "image file"
WINDOWS_PORTABLE_EXE = "Windows Portable Executable"
WINDOWS_HELP_FILE = "Windows Help File"
MSOFFICE_DOCUMENT = "Microsoft Office document"
OFFICE_OPEN_XML = "Office Open XML"
BZIP2_ARCHIVE_FILE = "BZIP2 Archive file"
ASCII_TEXT_FILE = "ASCII Text File"
ELF_EXE = "ELF Executable"

# Rulesets
LIPSUMPDF_YARA_RULESET = "%slorem_pdf.yara" % YARA_RULES_ROOT
GUANGGAO_YARA_RULESET = "%sguanggao_rules.yara" % YARA_RULES_ROOT
ZAP_PDF_YARA_RULESET = "%szap_pdf_rules.yara" % YARA_RULES_ROOT
MSOFFICE_YARA_RULESET = "%smsoffice_rules.yara" % YARA_RULES_ROOT
MSOFFICE_MACRO_YARA_RULESET = "%smsoffice_macro_rules.yara" % YARA_RULES_ROOT
MSOFFICEX_YARA_RULESET = "%smsofficex_rules.yara" % YARA_RULES_ROOT
CRYPTO_YARA_RULESET = "%scrypto.yar" % YARA_RULES_ROOT
PACKER_YARA_RULESET = "%spacker.yar" % YARA_RULES_ROOT
MULTIPLE_EMBED_PDF_RULESET = "{}{}".format(YARA_RULES_ROOT, "pdf_multiple_embed.yara")

# Files
LIPSUM_PDF_FILE = "lipsum.txt.pdf"
TXT_FILE = "test.txt"
BZ2_FILE = "test.txt.bz2"
GUANGGAO_GIF_FILE = "guanggao.gif"
GUANGGAO_GIF_BZ2_FILE = "guanggao.gif.bz2"
GUANGGAO_GIF_FILE2 = "pixel.gif"
ZAP_PDF_FILE = "ZAPGettingStartedGuide-2.4.pdf"
ZAP_PDF_TAR_FILE = "ZAPGettingStartedGuide-2.4.pdf.tar"
ZAP_PDF_GZIP_FILE = "ZAPGettingStartedGuide-2.4.pdf.gz"
ZAP_PDF_ZIP_FILE = "ZAPGettingStartedGuide-2.4.pdf.zip"
ZAP_PDF_ZIP_TARGZ_FILE = "ZAPGettingStartedGuide-2.4.pdf.zip.tar.gz"
MSOFFICE_DOC = "test_msoffice_word_doc.doc"
MSOFFICE_DOC_GZIP = "test_msoffice_word_doc.doc.gz"
MSOFFICE_DOC_GZIP_ZIP = "test_msoffice_word_doc.doc.gz.zip"
MSOFFICE_DOC_GZIP_ZIP_TARGZ = "test_msoffice_word_doc.doc.gz.zip.tar.gz"
MSOFFICEX_DOC = "Lorem-winlogon.docx"
MSOFFICEX_DOC_TAR = "Lorem-winlogon.docx.tar"
MSOFFICEX_DOC_TAR_ZIP = "Lorem-winlogon.docx.tar.zip"
MSOFFICEX_DOC_ZIP = "Lorem-winlogon.docx.zip"
MSOFFICEX_DOC_BZ2 = "Lorem-winlogon.docx.bz2"
MSOFFICEX_DOC_GZ = "Lorem-winlogon.docx.gz"
MSOFFICEX_DOC_GZ_ZIP = "Lorem-winlogon.docx.gz.zip"
MSOFFICEX_DOC_GZ_ZIP_TAR_GZ = "Lorem-winlogon.docx.gz.zip.tar.gz"
MSOFFICEX_DOC_GZ_ZIP_TAR_GZ_BZ2 = "Lorem-winlogon.docx.gz.zip.tar.gz.bz2"
MSOFFICEX_DOC_EXE = "embedded-exe.docx"
CRYPTO_DOC_EXE = "Test.docx"
CRYPTO_DOCM = "Test.docm"
CRYPTO_7Z = "Test.7z"
CRYPTO_DOC_BZ2 = "Test.docx.bz2"
CRYPTO_LIPSUM_ZIP = "Test.zip"
ZIP_7Z_FILE = "hmm.7z"
JPG_TAR_DLL = "trick.jpg"
MULTIPLE_EMBED_PDF = "pdf_with_multiple_embedded.pdf"
MZ_DLL = "System.dll"
MZ_EXE = "VirusShare_007f9182c475c9a049020b7307ec6d35"
PACKER_EXE = "VirusShare_0059ec457f9f173260d2dcad8f1fbdf7"
PACKER_EXE2 = "winlogon.exe"
PACKER_EXE3 = "spoolsy.exe"
ARCHIVE_RAR = "archive_test_rar.rar"
SO_FILE = "libnode.so"
PUTTY_EXE = "putty.exe"
PUTTY_EXE_ZIP = "putty.zip"

# Patterns
ZAP_PDF_PATTERN = "0x1880:$fg"
LOREM_BODY_PATTERN = "LOREM_FILE_BODY"
LIPSUM_LOREM_YARA_RULE_VAR = "$lipsum_pdf_body_lorem"
GUANGGAO_GIF_PATTERN1 = "0x0:$gif_image_file"
GUANGGAO_GIF_PATTERN2 = "0x6a96:$scriptbin"
GUANGGAO_GIF_PATTERN3 = "0x69f9:$iframebin"
MSOFFICE_BODY_FOOTER_PATTERN = "0x35f:$msoffice_doc_footer"
MSOFFICE_MACRO_PATTERN = "0x200a1:$obfuscation"
ADOBE_PDF_PATTERN = "ADOBE_PDF"
CRYPTO_PATTERN = "BLOWFISH_Constants"
CRYPTO_MD5_PATTERN = "MD5_Constants"
CRYPTO_RIPE_PATTERN = "RIPEMD160_Constants"
PACKER_PATTERN_1 = "0x10ce6:$a0"
PACKER_PATTERN_2 = "0x10ce6:$str1"
RANDOM_TXT_PATTERN = "0x1b:$text"
MZ_PATTERN = "MZ_PORTABLE_EXE"
EXE_PATTERN = "EXE_DROP"

######################################################

class Test_Yextend_files():

    '''
        GIF file with embedded javascript
    '''
    def test_yara_guanggao_gif(self):
        f_obj = TARG_DIR + GUANGGAO_GIF_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    pattern1_found = False
                    pattern2_found = False
                    pattern3_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if IMAGE_FILE in jj[SCAN_TYPE]:
                            if(GUANGGAO_GIF_PATTERN1 in jj[DETECTED_OFFSETS]):
                                pattern1_found = True
                            elif(GUANGGAO_GIF_PATTERN2 in jj[DETECTED_OFFSETS]):
                                pattern2_found = True
                            elif(GUANGGAO_GIF_PATTERN3 in jj[DETECTED_OFFSETS]):
                                pattern3_found = True
                    assert(pattern1_found and pattern2_found and pattern3_found)


    def test_yara_guanggao_gif_bz2(self):
        f_obj = TARG_DIR + GUANGGAO_GIF_BZ2_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    pattern1_found = False
                    pattern2_found = False
                    pattern3_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if IMAGE_FILE in jj[SCAN_TYPE]:
                            if(GUANGGAO_GIF_PATTERN1 in jj[DETECTED_OFFSETS]):
                                pattern1_found = True
                            elif(GUANGGAO_GIF_PATTERN2 in jj[DETECTED_OFFSETS]):
                                pattern2_found = True
                            elif(GUANGGAO_GIF_PATTERN3 in jj[DETECTED_OFFSETS]):
                                pattern3_found = True
                    assert(pattern1_found and pattern2_found and pattern3_found)


    def test_yara_guanggao_gif2(self):
        f_obj = TARG_DIR + GUANGGAO_GIF_FILE2
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
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
                        if IMAGE_FILE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    '''
        simple PDF
    '''
    def test_lipsum_pdf(self):
        f_obj = TARG_DIR + LIPSUM_PDF_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(LIPSUMPDF_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem1_found = False
                    lorem2_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            lorem1_found = jj[YARA_MATCHES_FOUND] == True
                        elif RAW_DATA in jj[SCAN_TYPE]:
                            lorem2_found = jj[YARA_MATCHES_FOUND] == True
                    assert(lorem1_found and lorem2_found)


    def test_lipsum_pdf_zip(self):
        f_obj = TARG_DIR + CRYPTO_LIPSUM_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(LIPSUMPDF_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem1_found = False
                    lorem2_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            lorem1_found = jj[YARA_MATCHES_FOUND] == True
                        elif RAW_DATA in jj[SCAN_TYPE]:
                            lorem2_found = jj[YARA_MATCHES_FOUND] == True
                    assert(lorem1_found and lorem2_found)


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


    def test_content_yara_zap_pdf_tar(self):
        f_obj = TARG_DIR + ZAP_PDF_TAR_FILE
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


    def test_content_yara_zap_pdf_gzip(self):
        f_obj = TARG_DIR + ZAP_PDF_GZIP_FILE
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
            lcmd = CMD_JSON_OUT.format(MSOFFICE_MACRO_YARA_RULESET, f_obj)
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
                        if MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    def test_content_yara_msoffice_doc_gzip_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC_GZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICE_MACRO_YARA_RULESET, f_obj)
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
                        if MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)



    def test_content_yara_msoffice_doc_gzip_zip_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC_GZIP_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICE_MACRO_YARA_RULESET, f_obj)
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
                        if MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)



    def test_content_yara_msoffice_doc_gzip_zip_targz_macro(self):
        f_obj = TARG_DIR + MSOFFICE_DOC_GZIP_ZIP_TARGZ
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICE_MACRO_YARA_RULESET, f_obj)
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
                        if MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    def test_content_yara_msofficex_doc(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_tar(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_TAR
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_tar_zip(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_TAR_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_zip(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_bz2(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_BZ2
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_gz(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_GZ
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_gz_zip(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_GZ_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_gz_zip_tar_gz(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_GZ_ZIP_TAR_GZ
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_msofficex_doc_gz_zip_tar_gz_bz2(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_GZ_ZIP_TAR_GZ_BZ2
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    '''
        word (.docx) file with header, footer,
        embedded pdf and 2 embedded windows executables (.exe)
    '''
    def test_content_yara_msofficex_doc_exe(self):
        f_obj = TARG_DIR + MSOFFICEX_DOC_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    adobe_pdf_pattern_found = False
                    exe_pattern_count = 0
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND]:
                            if OFFICE_OPEN_XML in jj[SCAN_TYPE] and LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif MSOFFICE_DOCUMENT in jj[SCAN_TYPE] and EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_count += 1
                            elif MSOFFICE_DOCUMENT in jj[SCAN_TYPE] and ADOBE_PDF_PATTERN in jj[YARA_RULE_ID]:
                                adobe_pdf_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(adobe_pdf_pattern_found)
                    assert(exe_pattern_count == 2)


    def test_content_yara_crypto_doc_exe(self):
        f_obj = TARG_DIR + CRYPTO_DOC_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)


    def test_content_yara_crypto_docm(self):
        f_obj = TARG_DIR + CRYPTO_DOCM
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)


    def test_content_yara_crypto_7z(self):
        f_obj = TARG_DIR + CRYPTO_7Z
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)


    def test_content_yara_crypto_zip(self):
        f_obj = TARG_DIR + CRYPTO_LIPSUM_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)


    def test_content_yara_crypto_doc_bz2(self):
        f_obj = TARG_DIR + CRYPTO_DOC_BZ2
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)


    def test_content_yara_packer_exe(self):
        f_obj = TARG_DIR + PACKER_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(PACKER_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    packer_pattern1_found = False
                    packer_pattern2_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            if PACKER_PATTERN_1 in jj[DETECTED_OFFSETS]:
                                packer_pattern1_found = True
                            elif PACKER_PATTERN_2 in jj[DETECTED_OFFSETS]:
                                packer_pattern2_found = True
                    assert(packer_pattern1_found)
                    assert(packer_pattern2_found)


    def test_content_yara_packer_exe2(self):
        f_obj = TARG_DIR + PACKER_EXE2
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(PACKER_YARA_RULESET, f_obj)
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
                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    def test_content_yara_packer_exe3(self):
        f_obj = TARG_DIR + PACKER_EXE3
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(PACKER_YARA_RULESET, f_obj)
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
                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    def test_content_yara_7z(self):
        f_obj = TARG_DIR + ZIP_7Z_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)



    def test_content_yara_msofficex_exe(self):
        f_obj = TARG_DIR + MZ_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
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
                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)


    def test_content_yara_dll(self):
        f_obj = TARG_DIR + MZ_DLL
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)


    def test_content_yara_jpg_tar_dll(self):
        f_obj = TARG_DIR + JPG_TAR_DLL
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = False
                    exe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found = True
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found = True
                    assert(lorem_body_pattern_found)
                    assert(exe_pattern_found)

    def test_yara_random_txt(self):
        f_obj = TARG_DIR + TXT_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
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
                        if ASCII_TEXT_FILE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_yara_random_bz2(self):
        f_obj = TARG_DIR + BZ2_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
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
                        if BZIP2_ARCHIVE_FILE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_yara_multiple_embedded_pdf(self):
        f_obj = TARG_DIR + MULTIPLE_EMBED_PDF
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MULTIPLE_EMBED_PDF_RULESET, "-t", f_obj, "-j"],
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

                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE] and CHILD_FILE_NAME in jj:
                            if jj[CHILD_FILE_NAME] == "bj.exe":
                                assert(jj[YARA_MATCHES_FOUND] == True)


    def test_yara_archive_rar_lipsum(self):
        f_obj = TARG_DIR + ARCHIVE_RAR
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(LIPSUMPDF_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem1_found = False
                    lorem2_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            lorem1_found = True
                        elif jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            lorem2_found = True
                    assert(lorem1_found and lorem2_found)


    def test_yara_archive_rar_msofficex(self):
        f_obj = TARG_DIR + ARCHIVE_RAR
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    win_exe_found = False
                    mz_exe_found = False
                    lorem_body_pattern_found = 0
                    exe_pattern_found = 0
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            if EXE_PATTERN in jj[YARA_RULE_ID]:
                                win_exe_found = True
                            elif MZ_PATTERN in jj[YARA_RULE_ID]:
                                mz_exe_found = True
                        elif jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            if LOREM_BODY_PATTERN == jj[YARA_RULE_ID]:
                                lorem_body_pattern_found += 1
                            elif EXE_PATTERN == jj[YARA_RULE_ID]:
                                exe_pattern_found += 1
                    assert(win_exe_found)
                    assert(mz_exe_found)
                    assert(lorem_body_pattern_found == 2)
                    assert(exe_pattern_found == 3)


    def test_yara_archive_rar_packer(self):
        f_obj = TARG_DIR + ARCHIVE_RAR
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(PACKER_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    win_exe_found = False
                    msdoc_found = 0
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            msdoc_found += 1
                        elif jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            win_exe_found = True
                    assert(win_exe_found)
                    assert(msdoc_found == 3)


    def test_yara_archive_rar_multiple_embed_pdf(self):
        f_obj = TARG_DIR + ARCHIVE_RAR
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MULTIPLE_EMBED_PDF_RULESET, "-t", f_obj, "-j"],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_body_pattern_found = 0
                    exe_pattern_found = 0
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and OFFICE_OPEN_XML in jj[SCAN_TYPE]:
                            lorem_body_pattern_found += 1
                        elif jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            exe_pattern_found += 1
                    assert(lorem_body_pattern_found == 2)
                    assert(exe_pattern_found == 3)

    def test_content_yara_7z_lipsum(self):
        f_obj = TARG_DIR + ZIP_7Z_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", LIPSUMPDF_YARA_RULESET, "-t", f_obj, "-j"],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem1_found = False
                    lorem2_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and RAW_DATA in jj[SCAN_TYPE]:
                            lorem1_found = True
                        elif jj[YARA_MATCHES_FOUND] and EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            lorem2_found = True
                    assert(lorem1_found)
                    assert(lorem2_found)

    def test_content_yara_7z_guanggao(self):
        f_obj = TARG_DIR + ZIP_7Z_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
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
                        if MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_content_yara_7z_crypto(self):
        f_obj = TARG_DIR + ZIP_7Z_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and MSOFFICE_DOCUMENT in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)

    def test_content_yara_7z_multiple_embed_pdf(self):
        f_obj = TARG_DIR + ZIP_7Z_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MULTIPLE_EMBED_PDF_RULESET, "-t", f_obj, "-j"],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    lorem_pattern1_found = False
                    lorem_pattern2_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and RAW_DATA in jj[SCAN_TYPE]:
                            lorem_pattern1_found = True
                        elif jj[YARA_MATCHES_FOUND] and EXTRACTED_TEXT in jj[SCAN_TYPE]:
                            lorem_pattern2_found = True
                    assert(lorem_pattern1_found == True)
                    assert(lorem_pattern2_found == True)

    def test_content_yara_so_msoffice(self):
        f_obj = TARG_DIR + SO_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICE_YARA_RULESET, f_obj)
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
                        if ELF_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_content_yara_so_crypto(self):
        f_obj = TARG_DIR + SO_FILE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and ELF_EXE in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)

    def test_content_yara_putty_guanggao(self):
        f_obj = TARG_DIR + PUTTY_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
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
                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_content_yara_putty_msofficex(self):
        f_obj = TARG_DIR + PUTTY_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
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
                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_content_yara_putty_crypto(self):
        f_obj = TARG_DIR + PUTTY_EXE
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)

    def test_content_yara_putty_multiple_embed_pdf(self):
        f_obj = TARG_DIR + PUTTY_EXE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MULTIPLE_EMBED_PDF_RULESET, "-t", f_obj, "-j"],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    pattern_found = 0
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            pattern_found += 1
                    assert(pattern_found == 4)

    def test_content_yara_putty_zip_guanggao(self):
        f_obj = TARG_DIR + PUTTY_EXE_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(GUANGGAO_YARA_RULESET, f_obj)
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
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_RULE_ID] == SEARCH_RANDOM_TEXT)

    def test_content_yara_putty_zip_msofficex(self):
        f_obj = TARG_DIR + PUTTY_EXE_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(MSOFFICEX_YARA_RULESET, f_obj)
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
                        if WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            assert(jj[YARA_MATCHES_FOUND] == True)

    def test_content_yara_putty_zip_crypto(self):
        f_obj = TARG_DIR + PUTTY_EXE_ZIP
        if os.path.isfile(f_obj):
            lcmd = CMD_JSON_OUT.format(CRYPTO_YARA_RULESET, f_obj)
            proc = Popen(lcmd.split(),
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    crypto_pattern_found = False
                    crypto_md5_pattern_found = False
                    crypto_ripe_pattern_found = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            if CRYPTO_PATTERN == jj[YARA_RULE_ID]:
                                crypto_pattern_found = True
                            elif CRYPTO_MD5_PATTERN == jj[YARA_RULE_ID]:
                                crypto_md5_pattern_found = True
                            elif CRYPTO_RIPE_PATTERN == jj[YARA_RULE_ID]:
                                crypto_ripe_pattern_found = True
                    assert(crypto_pattern_found)
                    assert(crypto_md5_pattern_found)
                    assert(crypto_ripe_pattern_found)

    def test_content_yara_putty_zip_multiple_embed_pdf(self):
        f_obj = TARG_DIR + PUTTY_EXE_ZIP
        if os.path.isfile(f_obj):
            proc = Popen([CMD, "-r", MULTIPLE_EMBED_PDF_RULESET, "-t", f_obj, "-j"],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            json_resp = json.loads(out)
            for jresp in json_resp:
                if SCAN_RESULTS in jresp:
                    pattern_found = 0
                    detection_embedded = False
                    for jj in jresp[SCAN_RESULTS]:
                        if jj[YARA_MATCHES_FOUND] and WINDOWS_PORTABLE_EXE in jj[SCAN_TYPE]:
                            pattern_found += 1
                        elif jj[YARA_MATCHES_FOUND] and WINDOWS_HELP_FILE in jj[SCAN_TYPE]:
                            detection_embedded = True
                    assert(pattern_found == 24)
                    assert(detection_embedded == True)

