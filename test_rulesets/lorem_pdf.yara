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


