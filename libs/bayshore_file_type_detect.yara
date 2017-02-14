rule GOODWILL_GUESS_ENCRYPTED_FILE_DETECTED_0
{
    meta:
        type = "Goodwill guess  Encrypted file detected"
        bayshore_ix = 0
        offset = 0
    strings:
        $goodwill_guess_encrypted_file_detected = { AA BB CC }
    condition:
        $goodwill_guess_encrypted_file_detected
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

rule MICROSOFT_OFFICE_OPEN_XML_FORMAT_DOCUMENT_DOCX_PPTX_XLSX_0
{
    meta:
        type = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)"
        bayshore_ix = 3
        offset = 0
    strings:
        $microsoft_office_open_xml_format_document_docx_pptx_xlsx = { 50 4b 03 04 14 00 06 00 08 00 00 00 21 00 }
    condition:
        $microsoft_office_open_xml_format_document_docx_pptx_xlsx
}

rule MICROSOFT_OFFICE_DOCUMENT_DOC_PPT_XLS_0
{
    meta:
        type = "Microsoft Office document (DOC PPT XLS)"
        bayshore_ix = 4
        offset = 0
    strings:
        $microsoft_office_document_doc_ppt_xls = { d0 cf 11 e0 a1 b1 1a e1 }
    condition:
        $microsoft_office_document_doc_ppt_xls
}

rule RAR_ARCHIVE_0
{
    meta:
        type = "RAR Archive"
        bayshore_ix = 6
        offset = 0
    strings:
        $rar_archive = { 52 45 7e 5e }
    condition:
        $rar_archive
}

rule RAR_ARCHIVE_1
{
    meta:
        type = "RAR Archive"
        bayshore_ix = 7
        offset = 0
    strings:
        $rar_archive = { 52 61 72 21 1a 07 00 cf }
    condition:
        $rar_archive
}

rule RAR_ARCHIVE_2
{
    meta:
        type = "RAR Archive"
        bayshore_ix = 8
        offset = 0
    strings:
        $rar_archive = { 52 61 72 21 1a 07 00 ff ff ff cf }
    condition:
        $rar_archive
}

rule RAR_ARCHIVE_PART_1_OF_MULTIPLE_FILES_0
{
    meta:
        type = "RAR Archive (Part 1 of Multiple Files)"
        bayshore_ix = 9
        offset = 0
    strings:
        $rar_archive_part_1_of_multiple_files = { 52 61 72 21 1a 07 00 5a }
    condition:
        $rar_archive_part_1_of_multiple_files
}

rule RAR_ARCHIVE_SUBSEQUENT_PART_OF_MULTIPLE_FILES_0
{
    meta:
        type = "RAR Archive (Subsequent Part of Multiple Files)"
        bayshore_ix = 10
        offset = 0
    strings:
        $rar_archive_subsequent_part_of_multiple_files = { 52 61 72 21 1a 07 00 19 }
    condition:
        $rar_archive_subsequent_part_of_multiple_files
}

rule ENCRYPTED_RAR_ARCHIVE_0
{
    meta:
        type = "Encrypted RAR Archive"
        bayshore_ix = 11
        offset = 0
    strings:
        $encrypted_rar_archive = { 52 61 72 21 1a 07 00 ce }
    condition:
        $encrypted_rar_archive
}

rule ENCRYPTED_RAR_ARCHIVE_1
{
    meta:
        type = "Encrypted RAR Archive"
        bayshore_ix = 12
        offset = 0
    strings:
        $encrypted_rar_archive = { 52 61 72 21 1a 07 00 ff ff ff ce }
    condition:
        $encrypted_rar_archive
}

rule ENCRYPTED_RAR_ARCHIVE_PART_1_OF_MULTIPLE_FILES_0
{
    meta:
        type = "Encrypted RAR Archive (Part 1 of Multiple Files)"
        bayshore_ix = 13
        offset = 0
    strings:
        $encrypted_rar_archive_part_1_of_multiple_files = { 52 61 72 21 1a 07 00 5b }
    condition:
        $encrypted_rar_archive_part_1_of_multiple_files
}

rule ENCRYPTED_RAR_ARCHIVE_SUBSEQUENT_PART_OF_MULTIPLE_FILES_0
{
    meta:
        type = "Encrypted RAR Archive (Subsequent Part of Multiple Files)"
        bayshore_ix = 14
        offset = 0
    strings:
        $encrypted_rar_archive_subsequent_part_of_multiple_files = { 52 61 72 21 1a 07 00 18 }
    condition:
        $encrypted_rar_archive_subsequent_part_of_multiple_files
}

rule JAR_ARCHIVE_0
{
    meta:
        type = "Jar Archive"
        bayshore_ix = 16
        offset = 0
    strings:
        $jar_archive = { 5f 27 a8 89 }
    condition:
        $jar_archive
}

rule GZIP_ARCHIVE_0
{
    meta:
        type = "GZIP Archive"
        bayshore_ix = 17
        offset = 0
    strings:
        $gzip_archive = { 1f ff ff ff 8b 08 }
    condition:
        $gzip_archive at 0
}

rule GZIP_ARCHIVE_1
{
    meta:
        type = "GZIP Archive"
        bayshore_ix = 18
        offset = 0
    strings:
        $gzip_archive = { 1f 8b 08 }
    condition:
        $gzip_archive at 0
}

rule COMPRESSED_TAPE_ARCHIVE_TARZ_0
{
    meta:
        type = "Compressed Tape Archive (TARZ)"
        bayshore_ix = 19
        offset = 0
    strings:
        $compressed_tape_archive_tarz = { 1f 9d 90 }
    condition:
        $compressed_tape_archive_tarz at 0
}

rule COMPRESSED_TAPE_ARCHIVE_TARZ_1
{
    meta:
        type = "Compressed Tape Archive (TARZ)"
        bayshore_ix = 20
        offset = 0
    strings:
        $compressed_tape_archive_tarz = { 1f a0 }
    condition:
        $compressed_tape_archive_tarz at 0
}

rule SEVENZIP_COMPRESSED_FILE_0
{
    meta:
        type = "7-Zip compressed file"
        bayshore_ix = 21
        offset = 0
    strings:
        $7zip_compressed_file = { 37 7a bc af 27 1c }
    condition:
        $7zip_compressed_file
}

rule HTML_FILE_0
{
    meta:
        type = "HTML File"
        bayshore_ix = 22
        offset = 0
    strings:
        $html_file = { 3c 68 74 6d 6c }
    condition:
        $html_file
}

rule HTML_FILE_1
{
    meta:
        type = "HTML File"
        bayshore_ix = 23
        offset = 0
    strings:
        $html_file = { 3c 48 54 4d 4c }
    condition:
        $html_file
}

rule HTML_FILE_2
{
    meta:
        type = "HTML File"
        bayshore_ix = 24
        offset = 0
    strings:
        $html_file = { 3c 21 44 4f 43 54 59 50 45 20 68 74 6d 6c }
    condition:
        $html_file
}

rule HTML_FILE_3
{
    meta:
        type = "HTML File"
        bayshore_ix = 25
        offset = 0
    strings:
        $html_file = { 3c 21 44 4f 43 54 59 50 45 20 48 54 4d 4c }
    condition:
        $html_file
}

rule WINDOWS_EXECUTABLE_0
{
    meta:
        type = "Windows Executable"
        bayshore_ix = 26
        offset = 0
    strings:
        $windows_executable = { 4d 5a }
    condition:
        $windows_executable at 0
}

rule WINDOWS_EXECUTABLE_1
{
    meta:
        type = "Windows Executable"
        bayshore_ix = 27
        offset = 0
    strings:
        $windows_executable = { 00 4d 5a }
    condition:
        $windows_executable at 0
}

rule MICROSOFT_OFFICE_OPEN_XML_FORMAT_DOCUMENT_DOCX_PPTX_XLSX_1
{
    meta:
        type = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)"
        bayshore_ix = 28
        offset = 0
    strings:
        $microsoft_office_open_xml_format_document_docx_pptx_xlsx = { 50 4b 03 04 14 00 08 08 08 00 }
    condition:
        $microsoft_office_open_xml_format_document_docx_pptx_xlsx
}

rule ASCII_TEXT_FILE_0
{
    meta:
        type = "ASCII Text File"
        bayshore_ix = 29
        offset = 0
    strings:
        $ascii_text_file = { AA BB CC }
    condition:
        $ascii_text_file
}

rule ENCRYPTED_RAR_ARCHIVE_2
{
    meta:
        type = "Encrypted RAR Archive"
        bayshore_ix = 30
        offset = 0
    strings:
        $encrypted_rar_archive = { 52 61 72 21 1a 07 00 15 }
    condition:
        $encrypted_rar_archive
}

rule PHP_SOURCE_CODE_0
{
    meta:
        type = "PHP Source Code"
        bayshore_ix = 31
        offset = 0
    strings:
        $php_source_code = { 3c 3f 70 68 70 }
    condition:
        $php_source_code
}

rule PHP_SOURCE_CODE_1
{
    meta:
        type = "PHP Source Code"
        bayshore_ix = 32
        offset = 0
    strings:
        $php_source_code = { 3c 3f }
    condition:
        $php_source_code at 0
}

rule JPEG_IMAGE_FILE_0
{
    meta:
        type = "JPEG image file"
        bayshore_ix = 33
        offset = 0
    strings:
        $jpeg_image_file = { ff d8 ff e0 }
    condition:
        $jpeg_image_file
}

rule JPEG_EXIF_IMAGE_FILE_0
{
    meta:
        type = "JPEG (EXIF) image file"
        bayshore_ix = 34
        offset = 0
    strings:
        $jpeg_exif_image_file = { ff d8 ff e1 }
    condition:
        $jpeg_exif_image_file
}

rule JPEG_SPIFF_IMAGE_FILE_0
{
    meta:
        type = "JPEG (SPIFF) image file"
        bayshore_ix = 35
        offset = 0
    strings:
        $jpeg_spiff_image_file = { ff d8 ff e8 }
    condition:
        $jpeg_spiff_image_file
}

rule JPEG2000_IMAGE_FILE_0
{
    meta:
        type = "JPEG2000 image file"
        bayshore_ix = 36
        offset = 0
    strings:
        $jpeg2000_image_file = { 00 00 00 0c 6a 50 20 20 }
    condition:
        $jpeg2000_image_file
}

rule BITMAP_IMAGE_FILE_0
{
    meta:
        type = "Bitmap image file"
        bayshore_ix = 37
        offset = 0
    strings:
        $bitmap_image_file = { 42 4d }
    condition:
        $bitmap_image_file at 0
}

rule GIF_IMAGE_FILE_0
{
    meta:
        type = "GIF image file"
        bayshore_ix = 38
        offset = 0
    strings:
        $gif_image_file = { 47 49 46 38 }
    condition:
        $gif_image_file
}

rule TIFF_IMAGE_FILE_0
{
    meta:
        type = "TIFF image file"
        bayshore_ix = 39
        offset = 0
    strings:
        $tiff_image_file = { 4d 4d 00 2a }
    condition:
        $tiff_image_file
}

rule TIFF_IMAGE_FILE_1
{
    meta:
        type = "TIFF image file"
        bayshore_ix = 40
        offset = 0
    strings:
        $tiff_image_file = { 4d 4d 00 2b }
    condition:
        $tiff_image_file
}

rule TIFF_IMAGE_FILE_2
{
    meta:
        type = "TIFF image file"
        bayshore_ix = 41
        offset = 0
    strings:
        $tiff_image_file = { 49 20 49 }
    condition:
        $tiff_image_file
}

rule TIFF_IMAGE_FILE_3
{
    meta:
        type = "TIFF image file"
        bayshore_ix = 42
        offset = 0
    strings:
        $tiff_image_file = { 49 49 2a 00 }
    condition:
        $tiff_image_file
}

rule PNG_IMAGE_FILE_0
{
    meta:
        type = "PNG image file"
        bayshore_ix = 43
        offset = 0
    strings:
        $png_image_file = { 89 50 4e 47 0d 0a 1a 0a }
    condition:
        $png_image_file
}

rule OPEN_DOCUMENT_FORMAT_ODF_DOCUMENT_0
{
    meta:
        type = "Open Document Format (ODF) document"
        bayshore_ix = 44
        offset = 0
    strings:
        $open_document_format_odf_document = { 50 4b 03 04 14 00 00 08 00 00 }
    condition:
        $open_document_format_odf_document
}

rule XML_DOCUMENT_0
{
    meta:
        type = "XML Document"
        bayshore_ix = 45
        offset = 0
    strings:
        $xml_document = { 3c 3f 78 6d 6c }
    condition:
        $xml_document
}

rule TAR_ARCHIVE_0
{
    meta:
        type = "TAR Archive"
        bayshore_ix = 46
        offset = 257
    strings:
        $tar_archive = { 75 73 74 61 72 }
    condition:
        $tar_archive
}

rule PCAP_FILE_0
{
    meta:
        type = "PCAP file"
        bayshore_ix = 47
        offset = 0
    strings:
        $pcap_file = { a1 b2 c3 d4 }
    condition:
        $pcap_file at 0
}

rule PCAP_FILE_1
{
    meta:
        type = "PCAP file"
        bayshore_ix = 48
        offset = 0
    strings:
        $pcap_file = { d4 c3 b2 a1 }
    condition:
        $pcap_file at 0
}

rule MICROSOFT_OFFICE_OPEN_XML_FORMAT_DOCUMENT_DOCX_PPTX_XLSX_2
{
    meta:
        type = "Microsoft Office Open XML Format Document (DOCX PPTX XLSX)"
        bayshore_ix = 50
        offset = 0
    strings:
        $microsoft_office_open_xml_format_document_docx_pptx_xlsx = { 50 4b 03 04 14 00 02 00 08 00 }
    condition:
        $microsoft_office_open_xml_format_document_docx_pptx_xlsx
}

rule MATLAB_5X_0
{
    meta:
        type = "MATLAB 5X"
        bayshore_ix = 51
        offset = 0
    strings:
        $matlab_5x = { 4d 41 54 4c 41 42 20 35 }
    condition:
        $matlab_5x
}

rule MATLAB_7X_0
{
    meta:
        type = "MATLAB 7X"
        bayshore_ix = 52
        offset = 0
    strings:
        $matlab_7x = { 4d 41 54 4c 41 42 20 37 }
    condition:
        $matlab_7x
}

rule CATIA_MODEL_0
{
    meta:
        type = "CATIA Model"
        bayshore_ix = 53
        offset = 0
    strings:
        $catia_model = { 56 35 5f 43 46 56 32 00 00 }
    condition:
        $catia_model
}

rule MUJAHIDEEN_SECRETS_2_ENCRYPTED_FILE_0
{
    meta:
        type = "Mujahideen Secrets 2 encrypted file"
        bayshore_ix = 54
        offset = 0
    strings:
        $mujahideen_secrets_2_encrypted_file = { 00 5c 41 b1 ff }
    condition:
        $mujahideen_secrets_2_encrypted_file
}

rule AUTOCAD_DRAWING_0
{
    meta:
        type = "AutoCAD Drawing"
        bayshore_ix = 55
        offset = 0
    strings:
        $autocad_drawing = { 41 43 31 30 }
    condition:
        $autocad_drawing
}

rule LOTUS_NOTES_DATABASE_0
{
    meta:
        type = "Lotus Notes Database"
        bayshore_ix = 56
        offset = 0
    strings:
        $lotus_notes_database = { 1a 00 00 04 00 00 }
    condition:
        $lotus_notes_database
}

rule LOTUS_NOTES_DATABASE_TEMPLATE_0
{
    meta:
        type = "Lotus Notes Database Template"
        bayshore_ix = 57
        offset = 0
    strings:
        $lotus_notes_database_template = { 1a 00 00 }
    condition:
        $lotus_notes_database_template at 0
}

rule MICROSOFT_OUTLOOK_PERSONAL_FOLDER_FILE_0
{
    meta:
        type = "Microsoft Outlook Personal Folder File"
        bayshore_ix = 58
        offset = 0
    strings:
        $microsoft_outlook_personal_folder_file = { 21 42 44 4e }
    condition:
        $microsoft_outlook_personal_folder_file
}

rule GENERIC_EMAIL_EML_FILE_0
{
    meta:
        type = "Generic E-Mail (EML) File"
        bayshore_ix = 59
        offset = 0
    strings:
        $generic_email_eml_file = { 46 72 6f 6d 20 3f 3f 3f }
    condition:
        $generic_email_eml_file
}

rule GENERIC_EMAIL_EML_FILE_1
{
    meta:
        type = "Generic E-Mail (EML) File"
        bayshore_ix = 60
        offset = 0
    strings:
        $generic_email_eml_file = { 46 72 6f 6d 20 20 20 }
    condition:
        $generic_email_eml_file
}

rule GENERIC_EMAIL_EML_FILE_2
{
    meta:
        type = "Generic E-Mail (EML) File"
        bayshore_ix = 61
        offset = 0
    strings:
        $generic_email_eml_file = { 46 72 6f 6d 3a 20 }
    condition:
        $generic_email_eml_file
}

rule GENERIC_EMAIL_EML_FILE_3
{
    meta:
        type = "Generic E-Mail (EML) File"
        bayshore_ix = 62
        offset = 0
    strings:
        $generic_email_eml_file = { 52 65 63 65 69 76 65 64 3a }
    condition:
        $generic_email_eml_file
}

rule GENERIC_EMAIL_EML_FILE_4
{
    meta:
        type = "Generic E-Mail (EML) File"
        bayshore_ix = 63
        offset = 0
    strings:
        $generic_email_eml_file = { 52 65 74 75 72 6e 2d 50 }
    condition:
        $generic_email_eml_file
}

rule OUTLOOK_EXPRESS_ADDRESS_BOOK_WIN95_0
{
    meta:
        type = "Outlook Express address book (Win95)"
        bayshore_ix = 64
        offset = 0
    strings:
        $outlook_express_address_book_win95 = { 81 32 84 c1 85 05 d0 11 b2 90 00 aa 00 3c f6 76 }
    condition:
        $outlook_express_address_book_win95
}

rule OUTLOOK_EXPRESS_EMAIL_FOLDER_0
{
    meta:
        type = "Outlook Express E-Mail Folder"
        bayshore_ix = 65
        offset = 0
    strings:
        $outlook_express_email_folder = { cf ad 12 fe }
    condition:
        $outlook_express_email_folder
}

rule OUTLOOK_ADDRESS_FILE_0
{
    meta:
        type = "Outlook Address File"
        bayshore_ix = 66
        offset = 0
    strings:
        $outlook_address_file = { 9c cb cb 8d 13 75 d2 11 95 58 00 c0 4f 79 56 a4 }
    condition:
        $outlook_address_file
}

rule OUTLOOK_ADDRESS_FILE_1
{
    meta:
        type = "Outlook Address File"
        bayshore_ix = 67
        offset = 0
    strings:
        $outlook_address_file = { 9c cb cb 8d 13 75 d2 11 }
    condition:
        $outlook_address_file at 0
}

rule PGP_GPG_PUBLIC_KEY_FILE_RSA_KEY_LENGTH_1024_0
{
    meta:
        type = "PGP/GPG Public Key File - RSA Key Length 1024"
        bayshore_ix = 68
        offset = 0
    strings:
        $pgp_gpg_public_key_file_rsa_key_length_1024 = { 98 8d 04 }
    condition:
        $pgp_gpg_public_key_file_rsa_key_length_1024
}

rule PGP_GPG_PUBLIC_KEY_FILE_RSA_KEY_LENGTH_2048_0
{
    meta:
        type = "PGP/GPG Public Key File - RSA Key Length 2048"
        bayshore_ix = 69
        offset = 0
    strings:
        $pgp_gpg_public_key_file_rsa_key_length_2048 = { 99 01 0d 04 }
    condition:
        $pgp_gpg_public_key_file_rsa_key_length_2048
}

rule PGP_GPG_PUBLIC_KEY_FILE_RSA_KEY_LENGTH_3072_0
{
    meta:
        type = "PGP/GPG Public Key File - RSA Key Length 3072"
        bayshore_ix = 70
        offset = 0
    strings:
        $pgp_gpg_public_key_file_rsa_key_length_3072 = { 99 01 8d 04 }
    condition:
        $pgp_gpg_public_key_file_rsa_key_length_3072
}

rule PGP_GPG_PUBLIC_KEY_FILE_RSA_KEY_LENGTH_4096_0
{
    meta:
        type = "PGP/GPG Public Key File - RSA Key Length 4096"
        bayshore_ix = 71
        offset = 0
    strings:
        $pgp_gpg_public_key_file_rsa_key_length_4096 = { 99 02 0d 04 }
    condition:
        $pgp_gpg_public_key_file_rsa_key_length_4096
}

rule PGP_GPG_PRIVATE_KEY_FILE_RSA_KEY_LENGTH_1024_0
{
    meta:
        type = "PGP/GPG Private Key File - RSA Key Length 1024"
        bayshore_ix = 72
        offset = 0
    strings:
        $pgp_gpg_private_key_file_rsa_key_length_1024 = { 95 01 d8 04 }
    condition:
        $pgp_gpg_private_key_file_rsa_key_length_1024
}

rule PGP_GPG_PRIVATE_KEY_FILE_RSA_KEY_LENGTH_2048_0
{
    meta:
        type = "PGP/GPG Private Key File - RSA Key Length 2048"
        bayshore_ix = 73
        offset = 0
    strings:
        $pgp_gpg_private_key_file_rsa_key_length_2048 = { 95 03 98 04 }
    condition:
        $pgp_gpg_private_key_file_rsa_key_length_2048
}

rule PGP_GPG_PRIVATE_KEY_FILE_RSA_KEY_LENGTH_3072_0
{
    meta:
        type = "PGP/GPG Private Key File - RSA Key Length 3072"
        bayshore_ix = 74
        offset = 0
    strings:
        $pgp_gpg_private_key_file_rsa_key_length_3072 = { 95 05 58 04 }
    condition:
        $pgp_gpg_private_key_file_rsa_key_length_3072
}

rule PGP_GPG_PRIVATE_KEY_FILE_RSA_KEY_LENGTH_4096_0
{
    meta:
        type = "PGP/GPG Private Key File - RSA Key Length 4096"
        bayshore_ix = 75
        offset = 0
    strings:
        $pgp_gpg_private_key_file_rsa_key_length_4096 = { 95 07 18 04 }
    condition:
        $pgp_gpg_private_key_file_rsa_key_length_4096
}

rule PGP_GPG_PRIVATE_KEY_FILE_PASSWORD_PROTECTED_RSA_KEY_LENGTH_1024_0
{
    meta:
        type = "PGP/GPG Private Key File (password protected) - RSA Key Length 1024"
        bayshore_ix = 76
        offset = 0
    strings:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_1024 = { 95 01 fe 04 }
    condition:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_1024
}

rule PGP_GPG_PRIVATE_KEY_FILE_PASSWORD_PROTECTED_RSA_KEY_LENGTH_2048_0
{
    meta:
        type = "PGP/GPG Private Key File (password protected) - RSA Key Length 2048"
        bayshore_ix = 77
        offset = 0
    strings:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_2048 = { 95 03 be 04 }
    condition:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_2048
}

rule PGP_GPG_PRIVATE_KEY_FILE_PASSWORD_PROTECTED_RSA_KEY_LENGTH_3072_0
{
    meta:
        type = "PGP/GPG Private Key File (password protected) - RSA Key Length 3072"
        bayshore_ix = 78
        offset = 0
    strings:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_3072 = { 95 05 7e 04 }
    condition:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_3072
}

rule PGP_GPG_PRIVATE_KEY_FILE_PASSWORD_PROTECTED_RSA_KEY_LENGTH_4096_0
{
    meta:
        type = "PGP/GPG Private Key File (password protected) - RSA Key Length 4096"
        bayshore_ix = 79
        offset = 0
    strings:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_4096 = { 95 07 3d 04 }
    condition:
        $pgp_gpg_private_key_file_password_protected_rsa_key_length_4096
}

rule PGP_GPG_ENCRYPTED_FILE_RSA_KEY_LENGTH_1024_0
{
    meta:
        type = "PGP/GPG Encrypted File - RSA Key Length 1024"
        bayshore_ix = 80
        offset = 0
    strings:
        $pgp_gpg_encrypted_file_rsa_key_length_1024 = { 84 8c 03 }
    condition:
        $pgp_gpg_encrypted_file_rsa_key_length_1024
}

rule PGP_GPG_ENCRYPTED_FILE_RSA_KEY_LENGTH_2048_0
{
    meta:
        type = "PGP/GPG Encrypted File - RSA Key Length 2048"
        bayshore_ix = 81
        offset = 0
    strings:
        $pgp_gpg_encrypted_file_rsa_key_length_2048 = { 85 01 0c 03 }
    condition:
        $pgp_gpg_encrypted_file_rsa_key_length_2048
}

rule PGP_GPG_ENCRYPTED_FILE_RSA_KEY_LENGTH_3072_0
{
    meta:
        type = "PGP/GPG Encrypted File - RSA Key Length 3072"
        bayshore_ix = 82
        offset = 0
    strings:
        $pgp_gpg_encrypted_file_rsa_key_length_3072 = { 85 01 8c 03 }
    condition:
        $pgp_gpg_encrypted_file_rsa_key_length_3072
}

rule PGP_GPG_ENCRYPTED_FILE_RSA_KEY_LENGTH_4096_0
{
    meta:
        type = "PGP/GPG Encrypted File - RSA Key Length 4096"
        bayshore_ix = 83
        offset = 0
    strings:
        $pgp_gpg_encrypted_file_rsa_key_length_4096 = { 85 02 0c 03 }
    condition:
        $pgp_gpg_encrypted_file_rsa_key_length_4096
}

rule PGP_ENCRYPTED_MESSAGE_CIPHERTEXT_0
{
    meta:
        type = "PGP Encrypted Message (ciphertext)"
        bayshore_ix = 84
        offset = 0
    strings:
        $pgp_encrypted_message_ciphertext = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 47 50 20 4d 45 53 53 41 47 45 2d 2d 2d 2d 2d }
    condition:
        $pgp_encrypted_message_ciphertext
}

rule PGP_PUBLIC_KEY_BLOCK_0
{
    meta:
        type = "PGP Public Key Block"
        bayshore_ix = 85
        offset = 0
    strings:
        $pgp_public_key_block = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 47 50 20 50 55 42 4c 49 43 20 4b 45 59 20 42 4c 4f 43 4b 2d 2d 2d 2d 2d }
    condition:
        $pgp_public_key_block
}

rule PGP_PRIVATE_KEY_BLOCK_0
{
    meta:
        type = "PGP Private Key Block"
        bayshore_ix = 86
        offset = 0
    strings:
        $pgp_private_key_block = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 47 50 20 50 52 49 56 41 54 45 20 4b 45 59 20 42 4c 4f 43 4b 2d 2d 2d 2d 2d }
    condition:
        $pgp_private_key_block
}

rule PCAP_FILE_3
{
    meta:
        type = "PCAP file"
        bayshore_ix = 87
        offset = 0
    strings:
        $pcap_file = { 34 cd b2 a1 }
    condition:
        $pcap_file
}

rule PCAP_FILE_4
{
    meta:
        type = "PCAP file"
        bayshore_ix = 88
        offset = 0
    strings:
        $pcap_file = { a1 b2 cd 34 }
    condition:
        $pcap_file
}

rule PCAPNG_FILE_0
{
    meta:
        type = "PCAPNG file"
        bayshore_ix = 89
        offset = 0
    strings:
        $pcapng_file = { 0a 0d 0d 0a }
    condition:
        $pcapng_file at 0
}

rule WINDOWS_POLICY_ADMINISTRATIVE_TEMPLATE_0
{
    meta:
        type = "Windows Policy Administrative Template"
        bayshore_ix = 90
        offset = 0
    strings:
        $windows_policy_administrative_template = { ff fe 43 00 4c 00 41 00 53 00 53 00 20 00 }
    condition:
        $windows_policy_administrative_template
}

rule WINDOWS_POLICY_ADMINISTRATIVE_TEMPLATE_1
{
    meta:
        type = "Windows Policy Administrative Template"
        bayshore_ix = 91
        offset = 0
    strings:
        $windows_policy_administrative_template = { 3b }
    condition:
        $windows_policy_administrative_template at 0
}

rule WINDOWS_POLICY_ADMINISTRATIVE_TEMPLATE_2
{
    meta:
        type = "Windows Policy Administrative Template"
        bayshore_ix = 92
        offset = 0
    strings:
        $windows_policy_administrative_template = { 43 4c 41 53 53 20 }
    condition:
        $windows_policy_administrative_template
}

rule WINDOWS_GROUP_POLICY_ADMINISTRATIVE_TEMPLATE_0
{
    meta:
        type = "Windows Group Policy Administrative Template"
        bayshore_ix = 93
        offset = 0
    strings:
        $windows_group_policy_administrative_template = { ff fe 3c 00 3f 00 78 00 6d 00 6c 00 20 00 76 00 }
    condition:
        $windows_group_policy_administrative_template
}

rule CHINA_MOBILE_APPLICATION_0
{
    meta:
        type = "China Mobile Application"
        bayshore_ix = 94
        offset = 0
    strings:
        $china_mobile_application = { 4d 52 50 47 }
    condition:
        $china_mobile_application
}

rule WINDOWS_EXECUTABLE_2
{
    meta:
        type = "Windows Executable"
        bayshore_ix = 95
        offset = 0
    strings:
        $windows_executable = { 5a 4d }
    condition:
        $windows_executable at 0
}

rule ELF_EXECUTABLE_0
{
    meta:
        type = "ELF Executable"
        bayshore_ix = 96
        offset = 0
    strings:
        $elf_executable = { 7f 45 4c 46 }
    condition:
        $elf_executable
}

rule MACHO_32BIT_BIG_ENDIAN_0
{
    meta:
        type = "Mach-O 32-Bit Big Endian"
        bayshore_ix = 97
        offset = 0
    strings:
        $macho_32bit_big_endian = { fe ed fa ce }
    condition:
        $macho_32bit_big_endian
}

rule MACHO_32BIT_LITTLE_ENDIAN_0
{
    meta:
        type = "Mach-O 32-Bit Little Endian"
        bayshore_ix = 98
        offset = 0
    strings:
        $macho_32bit_little_endian = { ce fa ed fe }
    condition:
        $macho_32bit_little_endian
}

rule MACHO_64BIT_BIG_ENDIAN_0
{
    meta:
        type = "Mach-O 64-Bit Big Endian"
        bayshore_ix = 99
        offset = 0
    strings:
        $macho_64bit_big_endian = { fe ed fa cf }
    condition:
        $macho_64bit_big_endian
}

rule MACHO_64BIT_LITTLE_ENDIAN_0
{
    meta:
        type = "Mach-O 64-Bit Little Endian"
        bayshore_ix = 100
        offset = 0
    strings:
        $macho_64bit_little_endian = { cf fa ed fe }
    condition:
        $macho_64bit_little_endian
}

rule JAVA_BYTECODE_OR_MACHO_FAT_BINARY_0
{
    meta:
        type = "Java Bytecode or Mach-O FAT Binary"
        bayshore_ix = 101
        offset = 0
    strings:
        $java_bytecode_or_macho_fat_binary = { ca fe ba be }
    condition:
        $java_bytecode_or_macho_fat_binary
}

rule JAVA_BYTECODE_PACK200_COMPRESSION_0
{
    meta:
        type = "Java Bytecode (Pack200 compression)"
        bayshore_ix = 102
        offset = 0
    strings:
        $java_bytecode_pack200_compression = { ca fe d0 0d }
    condition:
        $java_bytecode_pack200_compression
}

rule JAVA_SERIALIZATION_DATA_0
{
    meta:
        type = "Java Serialization Data"
        bayshore_ix = 103
        offset = 0
    strings:
        $java_serialization_data = { ac ed }
    condition:
        $java_serialization_data at 0
}

rule MICROSOFT_NET_RESOURCE_FILE_0
{
    meta:
        type = "Microsoft Net Resource File"
        bayshore_ix = 104
        offset = 0
    strings:
        $microsoft_net_resource_file = { be ef ca ce }
    condition:
        $microsoft_net_resource_file
}

rule SHOCKWAVE_FLASH_FILE_SWF_0
{
    meta:
        type = "Shockwave Flash File (SWF)"
        bayshore_ix = 105
        offset = 0
    strings:
        $shockwave_flash_file_swf = { 43 57 53 }
    condition:
        $shockwave_flash_file_swf at 0
}

rule SHOCKWAVE_FLASH_FILE_SWF_1
{
    meta:
        type = "Shockwave Flash File (SWF)"
        bayshore_ix = 106
        offset = 0
    strings:
        $shockwave_flash_file_swf = { 46 57 53 }
    condition:
        $shockwave_flash_file_swf at 0
}

rule FLASH_VIDEO_FILE_FLV_0
{
    meta:
        type = "Flash Video File (FLV)"
        bayshore_ix = 107
        offset = 0
    strings:
        $flash_video_file_flv = { 46 4c 56 }
    condition:
        $flash_video_file_flv at 0
}

rule TORRENT_FILE_0
{
    meta:
        type = "Torrent File"
        bayshore_ix = 108
        offset = 0
    strings:
        $torrent_file = { 64 38 3a 61 6e 6e 6f 75 6e 63 65 }
    condition:
        $torrent_file
}

rule ZIP_ARCHIVE_0
{
    meta:
        type = "Zip Archive"
        bayshore_ix = 109
        offset = 0
    strings:
        $zip_archive = { 50 4b 05 06 }
    condition:
        $zip_archive
}

rule ZIP_ARCHIVE_1
{
    meta:
        type = "Zip Archive"
        bayshore_ix = 110
        offset = 0
    strings:
        $zip_archive = { 50 4b 07 08 }
    condition:
        $zip_archive
}

rule PKSFX_SELFEXTRACTING_ARCHIVE_0
{
    meta:
        type = "PKSFX Self-Extracting Archive"
        bayshore_ix = 111
        offset = 526
    strings:
        $pksfx_selfextracting_archive = { 50 4b 53 70 58 }
    condition:
        $pksfx_selfextracting_archive
}

rule PKLITE_COMPRESSED_ZIP_ARCHIVE_0
{
    meta:
        type = "PKLITE Compressed ZIP Archive"
        bayshore_ix = 112
        offset = 30
    strings:
        $pklite_compressed_zip_archive = { 50 4b 4c 49 54 45 }
    condition:
        $pklite_compressed_zip_archive
}

rule PUFFER_ENCRYPTED_ARCHIVE_0
{
    meta:
        type = "Puffer Encrypted Archive"
        bayshore_ix = 113
        offset = 0
    strings:
        $puffer_encrypted_archive = { 50 55 46 58 }
    condition:
        $puffer_encrypted_archive
}

rule PUFFER_ASCIIARMORED_ENCRYPTED_ARCHIVE_0
{
    meta:
        type = "Puffer ASCII-Armored Encrypted Archive"
        bayshore_ix = 114
        offset = 0
    strings:
        $puffer_asciiarmored_encrypted_archive = { 42 65 67 69 6e 20 50 75 66 66 65 72 20 44 61 74 61 0d 0a }
    condition:
        $puffer_asciiarmored_encrypted_archive
}

rule VIRTUALBOX_DISK_IMAGE_VDI_0
{
    meta:
        type = "VirtualBox Disk Image (VDI)"
        bayshore_ix = 115
        offset = 0
    strings:
        $virtualbox_disk_image_vdi = { 3c 3c 3c 20 }
    condition:
        $virtualbox_disk_image_vdi
}

rule VMWARE_3_VIRTUAL_DISK_0
{
    meta:
        type = "VMware 3 Virtual Disk"
        bayshore_ix = 116
        offset = 0
    strings:
        $vmware_3_virtual_disk = { 43 4f 57 44 }
    condition:
        $vmware_3_virtual_disk
}

rule VMWARE_4_VIRTUAL_DISK_0
{
    meta:
        type = "VMware 4 Virtual Disk"
        bayshore_ix = 117
        offset = 0
    strings:
        $vmware_4_virtual_disk = { 23 20 44 69 73 6b 20 44 }
    condition:
        $vmware_4_virtual_disk
}

rule VMWARE_4_VIRTUAL_DISK_1
{
    meta:
        type = "VMware 4 Virtual Disk"
        bayshore_ix = 118
        offset = 0
    strings:
        $vmware_4_virtual_disk = { 4b 44 4d }
    condition:
        $vmware_4_virtual_disk at 0
}

rule TIFF_IMAGE_FILE_4
{
    meta:
        type = "TIFF image file"
        bayshore_ix = 119
        offset = 0
    strings:
        $tiff_image_file = { 4d 4d 2a }
    condition:
        $tiff_image_file at 0
}

rule COMPILED_HTML_0
{
    meta:
        type = "Compiled HTML"
        bayshore_ix = 120
        offset = 0
    strings:
        $compiled_html = { 49 54 53 46 }
    condition:
        $compiled_html
}

rule WINDOWS_HELP_FILE_0
{
    meta:
        type = "Windows Help File"
        bayshore_ix = 121
        offset = 0
    strings:
        $windows_help_file = { 3f 5f 03 00 }
    condition:
        $windows_help_file
}

rule WINDOWS_HELP_FILE_1
{
    meta:
        type = "Windows Help File"
        bayshore_ix = 122
        offset = 0
    strings:
        $windows_help_file = { 4c 4e 02 00 }
    condition:
        $windows_help_file
}

rule SHELL_SCRIPT_SHEBANG_0
{
    meta:
        type = "Shell Script (shebang)"
        bayshore_ix = 123
        offset = 0
    strings:
        $shell_script_shebang = { 23 21 2f }
    condition:
        $shell_script_shebang
}

rule MPEG_VIDEO_FILE_0
{
    meta:
        type = "MPEG Video file"
        bayshore_ix = 124
        offset = 0
    strings:
        $mpeg_video_file = { 00 00 01 b3 }
    condition:
        $mpeg_video_file
}

rule MPEG_VIDEO_FILE_1
{
    meta:
        type = "MPEG Video file"
        bayshore_ix = 125
        offset = 0
    strings:
        $mpeg_video_file = { 00 00 01 ba }
    condition:
        $mpeg_video_file
}

rule MICROSOFT_WINDOWS_MEDIA_AUDIO_VIDEO_FILE_ASF_WMA_WMV_0
{
    meta:
        type = "Microsoft Windows Media Audio/Video File (ASF WMA WMV)"
        bayshore_ix = 126
        offset = 0
    strings:
        $microsoft_windows_media_audio_video_file_asf_wma_wmv = { 30 26 b2 75 8e 66 cf 11 }
    condition:
        $microsoft_windows_media_audio_video_file_asf_wma_wmv
}

rule WAVE_FILE_WAV_0
{
    meta:
        type = "Wave File (WAV)"
        bayshore_ix = 127
        offset = 8
    strings:
        $wave_file_wav = { 57 41 56 45 }
    condition:
        $wave_file_wav
}

rule AUDIO_VIDEO_INTERLEAVED_FILE_AVI_0
{
    meta:
        type = "Audio Video Interleaved File (AVI)"
        bayshore_ix = 128
        offset = 8
    strings:
        $audio_video_interleaved_file_avi = { 41 56 49 }
    condition:
        $audio_video_interleaved_file_avi at 8
}

rule REAL_AUDIO_METADATA_FILE_RAM_0
{
    meta:
        type = "Real Audio Metadata File (RAM)"
        bayshore_ix = 129
        offset = 0
    strings:
        $real_audio_metadata_file_ram = { 2e 72 61 fd }
    condition:
        $real_audio_metadata_file_ram
}

rule REALMEDIA_FILE_RM_0
{
    meta:
        type = "RealMedia File (RM)"
        bayshore_ix = 130
        offset = 0
    strings:
        $realmedia_file_rm = { 2e 52 4d 46 }
    condition:
        $realmedia_file_rm
}

rule QUICKTIME_MOVIE_0
{
    meta:
        type = "QuickTime Movie"
        bayshore_ix = 131
        offset = 4
    strings:
        $quicktime_movie = { 6d 6f 6f 76 }
    condition:
        $quicktime_movie
}

rule QUICKTIME_MOVIE_MP4_0
{
    meta:
        type = "QuickTime Movie (MP4)"
        bayshore_ix = 132
        offset = 4
    strings:
        $quicktime_movie_mp4 = { 66 74 79 70 69 73 6f 6d }
    condition:
        $quicktime_movie_mp4
}

rule QUICKTIME_MOVIE_3GP_0
{
    meta:
        type = "QuickTime Movie (3GP)"
        bayshore_ix = 133
        offset = 4
    strings:
        $quicktime_movie_3gp = { 66 74 79 70 33 67 70 34 }
    condition:
        $quicktime_movie_3gp
}

rule QUICKTIME_MOVIE_3GP_1
{
    meta:
        type = "QuickTime Movie (3GP)"
        bayshore_ix = 134
        offset = 4
    strings:
        $quicktime_movie_3gp = { 66 74 79 70 6d 6d 70 34 }
    condition:
        $quicktime_movie_3gp
}

rule QUICKTIME_APPLE_LOSSLESS_AUDIO_CODEC_FILE_M4A_0
{
    meta:
        type = "QuickTime - Apple Lossless Audio Codec file (M4A)"
        bayshore_ix = 135
        offset = 4
    strings:
        $quicktime_apple_lossless_audio_codec_file_m4a = { 66 74 79 70 4d 34 41 20 }
    condition:
        $quicktime_apple_lossless_audio_codec_file_m4a
}

rule QUICKTIME_MOVIE_M4V_0
{
    meta:
        type = "QuickTime Movie (M4V)"
        bayshore_ix = 136
        offset = 4
    strings:
        $quicktime_movie_m4v = { 66 74 79 70 4d 34 56 20 }
    condition:
        $quicktime_movie_m4v
}

rule QUICKTIME_MOVIE_MP4_1
{
    meta:
        type = "QuickTime Movie (MP4)"
        bayshore_ix = 137
        offset = 4
    strings:
        $quicktime_movie_mp4 = { 66 74 79 70 6d 70 34 31 }
    condition:
        $quicktime_movie_mp4
}

rule QUICKTIME_MOVIE_MP4_2
{
    meta:
        type = "QuickTime Movie (MP4)"
        bayshore_ix = 138
        offset = 4
    strings:
        $quicktime_movie_mp4 = { 66 74 79 70 6d 70 34 32 }
    condition:
        $quicktime_movie_mp4
}

rule QUICKTIME_MOVIE_MP4_3
{
    meta:
        type = "QuickTime Movie (MP4)"
        bayshore_ix = 139
        offset = 4
    strings:
        $quicktime_movie_mp4 = { 66 74 79 70 33 67 70 35 }
    condition:
        $quicktime_movie_mp4
}

rule QUICKTIME_MOVIE_MP4_4
{
    meta:
        type = "QuickTime Movie (MP4)"
        bayshore_ix = 140
        offset = 4
    strings:
        $quicktime_movie_mp4 = { 66 74 79 70 4d 53 4e 56 }
    condition:
        $quicktime_movie_mp4
}

rule QUICKTIME_MOVIE_MOV_0
{
    meta:
        type = "QuickTime Movie (MOV)"
        bayshore_ix = 141
        offset = 4
    strings:
        $quicktime_movie_mov = { 66 74 79 70 71 74 20 20 }
    condition:
        $quicktime_movie_mov
}

rule MPEG4_VIDEO_FILE_3GP5_0
{
    meta:
        type = "MPEG-4 Video File (3GP5)"
        bayshore_ix = 142
        offset = 4
    strings:
        $mpeg4_video_file_3gp5 = { 00 00 00 18 66 74 79 70 }
    condition:
        $mpeg4_video_file_3gp5
}

rule PGP_GPG_SIGNED_CONTENT_0
{
    meta:
        type = "PGP/GPG Signed Content"
        bayshore_ix = 143
        offset = 0
    strings:
        $pgp_gpg_signed_content = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 47 50 20 53 49 47 4e 41 54 55 52 45 2d 2d 2d 2d 2d }
    condition:
        $pgp_gpg_signed_content
}

rule JAVASCRIPT_OPEN_TAG
{
    meta:
        type = "Javascript open tag"
        bayshore_ix = 144
    strings:
        $scriptbin = { 3c 73 63 72 69 70 74 20 }
    condition:
        $scriptbin
}

rule JAVASCRIPT_CLOSE_TAG
{
    meta:
        type = "Javascript close tag"
        bayshore_ix = 145
    strings:
        $scriptbin = { 3c 2f 73 63 72 69 70 74 3e }
    condition:
        $scriptbin
}

rule IFRAME_OPEN_TAG
{
    meta:
        type = "Iframe open tag"
        bayshore_ix = 146
    strings:
        $iframebin = { 3c 69 66 72 61 6d 65 20 }
    condition:
        $iframebin
}

rule IFRAME_CLOSE_TAG
{
    meta:
        type = "Iframe close tag"
        bayshore_ix = 147
    strings:
        $iframebin = { 3c 2f 69 66 72 61 6d 65 3e }
    condition:
        $iframebin
}

rule MSOFFICE_MACRO
{
    meta:
        type = "MS_Office macro"
        bayshore_ix = 148
    strings:
        $msofficemacro = { 00 41 74 74 72 69 62 75 74 00 }
    condition:
        $msofficemacro
}

rule MPEG_1_AUDIO_FILE_MP3_0
{
    meta:
        type = "MPEG-1 Audio Layer 3 File (MP3)"
        bayshore_ix = 149
        offset = 0
    strings:
        $mpeg1_audio_file_mp3 = { 49 44 33 03 00 00 00 00 }
    condition:
        $mpeg1_audio_file_mp3
}

rule EXPERT_WITNESS_COMPRESSED_FILE_0
{
    meta:
        type = "Expert Witness Compression Formatted file (EWF)"
        bayshore_ix = 150
        offset = 0
    strings:
        $expert_witness_compressed_file = { 45 56 46 09 0d 0a ff 00 }
    condition:
        $expert_witness_compressed_file
}

rule ENCASE_EVIDENCE_FORMATTED_FILE_0
{
    meta:
        type = "EnCase Evidence File Format (Version 2)"
        bayshore_ix = 151
        offset = 0
    strings:
        $encase_evidence_formatted_file = { 45 56 46 32 0d 0a 81 }
    condition:
        $encase_evidence_formatted_file
}

rule ADOBE_POSTSCRIPT_0
{
    meta:
        type = "Adobe PostScript File (PS)"
        bayshore_ix = 152
        offset = 0
    strings:
        $adobe_postscript_file = { 25 21 50 53 2d 41 64 6f 62 65 2d ?? 2e 30 0a 25 25 }
    condition:
        $adobe_postscript_file
}

rule ADOBE_POSTSCRIPT_1
{
    meta:
        type = "Adobe PostScript File (PS)"
        bayshore_ix = 153
        offset = 0
    strings:
        $adobe_postscript_file = { 25 21 50 53 2d 41 64 6f 62 65 2d 0a 25 25 }
    condition:
        $adobe_postscript_file
}

rule ADOBE_ENCAPSULATED_POSTSCRIPT_0
{
    meta:
        type = "Adobe Encapsulated PostScript File (EPS)"
        bayshore_ix = 154
        offset = 0
    strings:
        $adobe_encapsulated_postscript_file = { 25 21 50 53 2d 41 64 6f 62 65 2d 33 2e 30 20 45 50 53 46 2d 33 ?? 30 }
    condition:
        $adobe_encapsulated_postscript_file
}

rule LNK_WINDOWS_SHELL
{
    meta:
    	type = "Windows shell link (shortcut) file"
        bayshore_ix = 155
        offset = 0
    strings:
        $lnk_windows_shell = { 4c 00 00 00 01 14 02 00 }
    condition:
        $lnk_windows_shell
}

rule MS_COFF_OBJECT
{
    meta:
    	type = "Microsoft Common Object File Format (COFF) relocatable object code file"
        bayshore_ix = 156
        offset = 0
    strings:
        $ms_coff_object = { 4c 01 }
    condition:
        $ms_coff_object
}

rule BZIP2_ARCHIVE
{
    meta:
        type = "bzip2 Compressed Archive"
        bayshore_ix = 157
        offset = 0
    strings:
        $bzip2_archive = { 42 5a 68 }
    condition:
        $bzip2_archive
}

rule ZIP_ARCHIVE_2
{
    meta:
        type = "Zip Archive"
        bayshore_ix = 65534
        offset = 0
    strings:
        $zip_archive = { 50 4b 03 04 }
    condition:
        $zip_archive
}

rule UNCLASSIFIED_BINARY_0
{
    meta:
        type = "Unclassified Binary"
        bayshore_ix = 65535
        offset = 0
    strings:
        $unclassified_binary = { AA BB CC }
    condition:
        $unclassified_binary
}

