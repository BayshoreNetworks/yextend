rule GIF_IMAGE_FILE
{
    meta:
        type = "GIF image file"
    strings:
        $gif_image_file = { 47 49 46 38 }
    condition:
        $gif_image_file
}

rule javascript_open_tag
{
    meta:
        type = "Javascript open tag"
    strings:
        $scriptbin = { 3c 73 63 72 69 70 74 20 }
    condition:
        $scriptbin
}

rule javascript_close_tag
{
    meta:
        type = "Javascript close tag"
    strings:
        $scriptbin = { 3c 2f 73 63 72 69 70 74 3e }
    condition:
        $scriptbin
}

rule iframe_open_tag
{
    meta:
        type = "Iframe open tag"
    strings:
        $iframebin = { 3c 69 66 72 61 6d 65 20 }
    condition:
        $iframebin
}

rule iframe_close_tag
{
    meta:
        type = "Iframe close tag"
    strings:
        $iframebin = { 3c 2f 69 66 72 61 6d 65 3e }
    condition:
        $iframebin
}

rule search_random_text
{
    meta:
        type = "Search random text"
    strings:
        $text = "random" nocase
    condition:
        $text
}
