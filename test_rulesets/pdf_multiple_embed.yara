import "pe"
import "hash"

rule gb_backdoor {
    meta:
        type = "Backdoor string detect"
    strings:
        $bd = "g_bDoBackdoor"
    condition:
        $bd
}

rule pdf_exe_netsvc {
    meta:
        type = "text string in pe exe"
    strings:
        $nets = "Netsvcs"
    condition:
        $nets
}

rule detection_embedded {
    meta:
        type = "text strings in pdf content"
    strings:
        $pdf1 = "detection"
        $pdf2 = "embedded"
    condition:
        $pdf1 and $pdf2
}

rule IsPE {
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and uint32(uint32(0x3C) + 4 + 20 + 4) != 0
        and pe.characteristics & pe.SYSTEM == 0
}

rule Not_64_bit {
    condition:
        IsPE and pe.machine == pe.MACHINE_I386
}


rule DEP_missing {
    meta:
        description = "DEP is not enabled"

    condition:
       IsPE and pe.dll_characteristics & pe.NX_COMPAT == 0

       // All 64-bit executables have DEP, so only check 32-bit
       and pe.machine == pe.MACHINE_I386

       // Also ensure this is not a DLL
       and pe.characteristics & pe.DLL == 0
}

rule ASLR_missing {
    meta:
        description = "ASLR is not enabled"

    condition:
       IsPE and pe.dll_characteristics & pe.DYNAMIC_BASE == 0
}

rule NETexecutableMicrosoft {
    meta:
        author="malware-lu"
    strings:
        $a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }
    condition:
        $a0
}

rule FILE_SIGS {

    meta:
        description = "Known malware signature"

    condition:
        hash.md5(0, filesize) == "00ac4c68eb5fd84f217cbf43e46387c6"   or  
        hash.md5(0, filesize) == "00b70bf3985a0c93a44a6848e1543dc0"   or 
        hash.md5(0, filesize) == "0aec500939cebf593f6cc8676197a81a"   or 
        hash.md5(0, filesize) == "0bda67dd0530bd2574f7c14e1397e5e8"   or
        hash.md5(0, filesize) == "368c8cbc67d3ce1ff7d2735cfe84f670" 
}

rule LOREM_FILE_BODY
{
    meta:
        type = "PDF body text (lorem)"
    strings:
        $lipsum_pdf_body_lorem = "lorem" nocase
    condition:
        $lipsum_pdf_body_lorem
}

rule invalid_trailer_structure : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                weight = 1

        strings:
                $magic = { 25 50 44 46 }
                                // Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic at 0 and not $reg0 and not $reg1
}



