rule CONFIDENTIAL_FILE_FOOTER
{
    meta:
        type = "MS Office DOC footer"
    strings:
        $msoffice_doc_footer = "confidential footer" nocase
    condition:
        $msoffice_doc_footer
}

rule LOREM_FILE_BODY
{
    meta:
        type = "MS Office DOC body (lorem)"
    strings:
        $msoffice_doc_body_lorem = "lorem" nocase
    condition:
        $msoffice_doc_body_lorem
}

rule FILE_HEADER
{
    meta:
        type = "MS Office DOC header"
    strings:
        $msoffice_doc_header = "header for" nocase
    condition:
        $msoffice_doc_header
}

rule EXE_DROP
{
	strings:
		$a  = "This program cannot be run in DOS mode"
	condition:
		all of them
}

rule MSDOS_EXE_FILE
{
	strings:
		$a  = "This program must be run under Win32"
	condition:
		all of them
}

rule MZ_PORTABLE_EXE
{
    condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550
}

rule ADOBE_PDF_0
{
    meta:
        type = "Adobe PDF"
        bayshore_ix = 1
        offset = 0
    strings:
        $adobe_pdf = { 25 50 44 46 }
    condition:
        $adobe_pdf
}