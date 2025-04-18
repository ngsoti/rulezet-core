//More at reversecodes.wordpress.com
rule DMALocker4.0
{
    meta:
    Description = "Deteccion del ransomware DMA Locker version 4.0"
    Author = "SadFud"
    Date = "30/05/2016"
	Hash = "e3106005a0c026fc969b46c83ce9aeaee720df1bb17794768c6c9615f083d5d1"
    
    strings:
    $clave = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    $clave 
    
}

rule Linux_Trojan_Skidmap_aa7b661d {
    meta:
        author = "Elastic Security"
        id = "aa7b661d-0ecc-4171-a0c2-a6c0c91b6d27"
        fingerprint = "0bd6bec14d4b0205b04c6b4f34988ad95161f954a1f0319dd33513cb2c7e5f59"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Skidmap"
        reference_sample = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 41 41 80 F8 1A 41 0F 43 C1 88 04 0E 48 83 C1 01 0F B6 04 0F }
    condition:
        all of them
}


rule: Satana_Ransomware
{
	 meta:
    Description = "Deteccion de ransomware Satana"
    Author = "SadFud"
    Date = "12/07/2016"
	
	strings:
	$satana = { !satana! } nocase
	
	condition:
	$satana
}