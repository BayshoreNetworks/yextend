rule lnk_file_extension {
    meta:
        description = "detected ink extension "
    strings:
        $Pattern1 = {4c0000000114020000000000c000000000000046}
    condition:
        $Pattern1
}
