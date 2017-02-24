rule BLAH_FILE_FOOTER
{
    meta:
        type = "MS Office DOC footer"
    strings:
        $msoffice_doc_footer = "blah" nocase
    condition:
        $msoffice_doc_footer
}

rule LOREM_FILE_BODY
{
    meta:
        type = "MS Office DOC body"
    strings:
        $msoffice_doc_body = "mel zril nominati" nocase
    condition:
        $msoffice_doc_body
}

