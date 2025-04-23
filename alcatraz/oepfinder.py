from qiling import Qiling
from qiling.const import QL_VERBOSE

# Qiling Version: 1.4.8
# IDA Pro Version 7.7

ROOTFS_PATH = r"ROOTFS_PATH"

def find_oep(sample_path, func) -> int:
    # I added the log_devices parameter because I got the following error.
    # TypeError: unexpected logging device type: IDAPythonStdOut
    ql = Qiling([sample_path], rootfs=ROOTFS_PATH, verbose=QL_VERBOSE.OFF, log_devices=[])
    # To prevent Qiling from continuing emulation, the RAX value 
    # must be taken one instruction before the jmp opcode is executed.
    ql.run(begin=func.start_ea, end=func.end_ea - 0x4) # - jmp opcode size
    original_entry_point = ql.arch.regs.read("RAX")
    print(f"[+] Found Original Entry Point: 0x{original_entry_point:x}")
    
    return original_entry_point

def main():
    print("[~] 0xReverse - Alcatraz Deobfuscator IDA Script [~]")
    sample_path = idaapi.get_input_file_path()
    # IDAPython CheatSheet
    # https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c
    info = idaapi.get_inf_structure()
    entrypoint = info.start_ea  # EntryPoint start address
    if func := ida_funcs.get_func(entrypoint):
        function_name = idc.get_func_name(entrypoint)
        print(f"[+] Emulating Function Name: {function_name}, Address: {entrypoint:x}")        
        original_entry_point = find_oep(sample_path, func)

        # Rename OEP address to original_entry_point
        idc.set_name(original_entry_point, "original_entry_point", idc.SN_NOWARN)
    else:
        print(f"[-] This address is not a function")
        exit(-1)

main()