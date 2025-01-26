rule MalwareDetection
{
    meta:
        description = "Detecte des comportements suspectes dans des executables"
        author = "Utilisateur"
        threat_level = "high"
        target_type = "PE file"
        date = "2025-01-26"
        references = "https://exemple.com/indicateurs"
    strings: 
        $pe_header = "This program cannot be run in DOS mode"
        $virtual_alloc = "virtualAlloc"
        $base64 = /[A-Za-z0-9+\/]{50,}=*/
        $http = "http://"
        $upx = "UPX0"
    condition:
        $pe_header and (2 of ($virtual_alloc, $base64, $http, $upx))
}