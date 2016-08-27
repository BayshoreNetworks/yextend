#****************************************************************************
#
# YEXTEND: Help for YARA users.
# This file is part of yextend.
#
# Copyright (c) 2014-2016, Bayshore Networks, Inc.
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
from subprocess import Popen, PIPE

######################################################
LD_LIBRARY_PATH = 'LD_LIBRARY_PATH'
LIB_PATHS = "/usr/local/lib"
CMD = "./yextend"

TARG_DIR = "test_files/"
YARA_RULES_ROOT = "test_rulesets/"

GUANGGAO_YARA_RULESET = "%sguanggao_rules.yara" % YARA_RULES_ROOT
LIPSUMPDF_YARA_RULESET = "%slorem_pdf.yara" % YARA_RULES_ROOT

GUANGGAO_FILE = "guanggao.gif"
LIPSUM_PDF_FILE = "lipsum.txt.pdf"

LIPSUM_LOREM_YARA_RULE_ID = "LOREM_FILE_BODY"
LIPSUM_LOREM_YARA_RULE_VAR = "$lipsum_pdf_body_lorem"
######################################################

class Test_Yextend_files():
    
    '''
        GIF file with embedded javascript
    '''
    def test_yara_guanggao_gif(self):
        f_obj = TARG_DIR + GUANGGAO_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, GUANGGAO_YARA_RULESET, f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            assert("0x0:$gif_image_file" in out and "0x6a96:$scriptbin" in out and "0x69f9:$iframebin" in out)
            #print out
            
    '''
        simple PDF
    '''
    def test_lipsum_pdf(self):
        f_obj = TARG_DIR + LIPSUM_PDF_FILE
        if os.path.isfile(f_obj):
            proc = Popen([CMD, LIPSUMPDF_YARA_RULESET, f_obj],
                         env={LD_LIBRARY_PATH:LIB_PATHS},
                         stdout=PIPE,
                         stderr=PIPE,
                         )
            out, err = proc.communicate()
            assert(LIPSUM_PDF_FILE in out and LIPSUM_LOREM_YARA_RULE_ID in out and out.count(LIPSUM_LOREM_YARA_RULE_VAR) > 1)
            #print out
        
  
            
            