rule zap_pdf_rule1
{
    meta:
        type = "text in pdf"
    strings:
        $fg = "fine grained"
    condition:
        $fg
}

rule zap_pdf_rule2
{
    meta:
        type = "text in pdf"
    strings:
        $fga = "add-ons"
    condition:
        $fga
}