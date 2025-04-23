import "pe"

rule SUSP_EXE_Alcatraz_Obfuscator_April_23 { 
    meta:
        description = "This rule detects samples obfuscated with Alcatraz."
        author      = "Utku Corbaci / 0xReverse"
        date        = "2025-04-23"
        sharing     = "TLP:CLEAR"
        tags        = "windows,exe,suspicious,obfuscator"
        os          = "Windows"

    strings:
        // B8 41 CD A8 27   mov     eax, 27A8CD41h
        // 66 9C            pushf
        // F7 D0            not     eax
        // 05 AB FD E1 DD   add     eax, 0DDE1FDABh
        // 35 CA 3C 0F BF   xor     eax, 0BF0F3CCAh
        // C1 C0 62         rol     eax, 62h
        // 66 9D            popf
        $obfuscation_mov = {B8 ?? ?? ?? ?? 66 9C F7 D0 05 ?? ?? ?? ?? 35 ?? ?? ?? ?? C1 C0 ?? 66 9D}

        // 48 8D 05 74 81 47 77	    lea     rax, cs:1B748621Eh
        // 66 9C               	    pushf
        // 48 2D A6 2B 48 77   	    sub     rax, 77482BA6h
        // 66 9D               	    popf
        $obfuscation_lea = {48 8D ?? ?? ?? ?? ?? 66 9C 48 2D ?? ?? ?? ?? 66 9D}
    condition: 
        pe.is_pe
        and for any i in (0..pe.number_of_sections - 1): (
		    (pe.sections[i].name == ".0Dev")
        )
        and (all of ($obfuscation_*))
}