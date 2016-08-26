'''

'''
import os
from subprocess import Popen, PIPE

######################################################
LD_LIBRARY_PATH = 'LD_LIBRARY_PATH'
LIB_PATHS = "/usr/local/lib"
CMD = "./yextend"

TARG_DIR = "test_files/"
YARA_RULES_ROOT = "test_rulesets/"

GUANGGAO_YARA_RULESET = "%sguanggao_rules.yara" % YARA_RULES_ROOT

GUANGGAO_FILE = "guanggao.gif"
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
            assert("0x0:$gif_image_file" in out)
            assert("0x6a96:$scriptbin" in out)
            assert("0x69f9:$iframebin" in out)
            #print out
        
  
            
            