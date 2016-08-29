rule LOREM_FILE_BODY
{
    meta:
        type = "PDF body text (lorem)"
    strings:
        $lipsum_pdf_body_lorem = "lorem" nocase
    condition:
        $lipsum_pdf_body_lorem
}

