rule elf_babuk_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects elf.babuk."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.babuk"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 658b0d00000000 8b89fcffffff 3b6108 7678 83ec14 8b442418 8b4c241c }
            // n = 7, score = 200
            //   658b0d00000000       | mov                 ecx, dword ptr gs:[0]
            //   8b89fcffffff         | mov                 ecx, dword ptr [ecx - 4]
            //   3b6108               | cmp                 esp, dword ptr [ecx + 8]
            //   7678                 | jbe                 0x7a
            //   83ec14               | sub                 esp, 0x14
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]

        $sequence_1 = { 8b4c2438 890f 8b542444 89570c 8b1d???????? 85db }
            // n = 6, score = 200
            //   8b4c2438             | mov                 ecx, dword ptr [esp + 0x38]
            //   890f                 | mov                 dword ptr [edi], ecx
            //   8b542444             | mov                 edx, dword ptr [esp + 0x44]
            //   89570c               | mov                 dword ptr [edi + 0xc], edx
            //   8b1d????????         |                     
            //   85db                 | test                ebx, ebx

        $sequence_2 = { e8???????? 8b44240c 89442410 8b4c2418 890c24 e8???????? 8b442420 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   890c24               | mov                 dword ptr [esp], ecx
            //   e8????????           |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]

        $sequence_3 = { e8???????? 8b442438 8b4804 90 8b492c 894c2420 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   90                   | nop                 
            //   8b492c               | mov                 ecx, dword ptr [ecx + 0x2c]
            //   894c2420             | mov                 dword ptr [esp + 0x20], ecx
            //   e8????????           |                     

        $sequence_4 = { c3 658b1d00000000 8b9bfcffffff 8b5b18 8b5b70 8403 890424 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   658b1d00000000       | mov                 ebx, dword ptr gs:[0]
            //   8b9bfcffffff         | mov                 ebx, dword ptr [ebx - 4]
            //   8b5b18               | mov                 ebx, dword ptr [ebx + 0x18]
            //   8b5b70               | mov                 ebx, dword ptr [ebx + 0x70]
            //   8403                 | test                byte ptr [ebx], al
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_5 = { 01d9 8b9c24a8010000 8bbc243c030000 01fb 11cd 8b8c248c010000 8b9c2464020000 }
            // n = 7, score = 200
            //   01d9                 | add                 ecx, ebx
            //   8b9c24a8010000       | mov                 ebx, dword ptr [esp + 0x1a8]
            //   8bbc243c030000       | mov                 edi, dword ptr [esp + 0x33c]
            //   01fb                 | add                 ebx, edi
            //   11cd                 | adc                 ebp, ecx
            //   8b8c248c010000       | mov                 ecx, dword ptr [esp + 0x18c]
            //   8b9c2464020000       | mov                 ebx, dword ptr [esp + 0x264]

        $sequence_6 = { 8b44244c 8b4c2440 31d2 eb06 8d5101 90 89f1 }
            // n = 7, score = 200
            //   8b44244c             | mov                 eax, dword ptr [esp + 0x4c]
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   31d2                 | xor                 edx, edx
            //   eb06                 | jmp                 8
            //   8d5101               | lea                 edx, [ecx + 1]
            //   90                   | nop                 
            //   89f1                 | mov                 ecx, esi

        $sequence_7 = { 895328 8b9424b0000000 8b8c2490000000 01ca 33562c 89532c }
            // n = 6, score = 200
            //   895328               | mov                 dword ptr [ebx + 0x28], edx
            //   8b9424b0000000       | mov                 edx, dword ptr [esp + 0xb0]
            //   8b8c2490000000       | mov                 ecx, dword ptr [esp + 0x90]
            //   01ca                 | add                 edx, ecx
            //   33562c               | xor                 edx, dword ptr [esi + 0x2c]
            //   89532c               | mov                 dword ptr [ebx + 0x2c], edx

        $sequence_8 = { 8b5a40 39d8 0f85360f0000 89bc2408020000 81c4dc010000 c3 89c7 }
            // n = 7, score = 200
            //   8b5a40               | mov                 ebx, dword ptr [edx + 0x40]
            //   39d8                 | cmp                 eax, ebx
            //   0f85360f0000         | jne                 0xf3c
            //   89bc2408020000       | mov                 dword ptr [esp + 0x208], edi
            //   81c4dc010000         | add                 esp, 0x1dc
            //   c3                   | ret                 
            //   89c7                 | mov                 edi, eax

        $sequence_9 = { 8b4c2424 01ca 89942444050000 8b8c2490050000 c1e11a 898c2420050000 }
            // n = 6, score = 200
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   01ca                 | add                 edx, ecx
            //   89942444050000       | mov                 dword ptr [esp + 0x544], edx
            //   8b8c2490050000       | mov                 ecx, dword ptr [esp + 0x590]
            //   c1e11a               | shl                 ecx, 0x1a
            //   898c2420050000       | mov                 dword ptr [esp + 0x520], ecx

    condition:
        7 of them and filesize < 4186112
}