import idautils


rol = lambda val, r_bits, max_bits: ((val << (r_bits % max_bits)) & (2**max_bits - 1)) | ((val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
ror = lambda val, r_bits, max_bits: ((val & (2**max_bits - 1)) >> (r_bits % max_bits)) | ((val << (max_bits - (r_bits % max_bits))) & (2**max_bits - 1))
MASK = 0xFFFFFFFF


def calculate_mov_value(init_value, add_value, xor_value, rol_value):
   # mov     eax, VALUE
   calculated_value = init_value
   # not     eax         -> bitwise NOT
   calculated_value = (~calculated_value) & MASK
   # add     eax, VALUE
   calculated_value = (calculated_value + add_value) & MASK
   # xor     eax, VALUE
   calculated_value = calculated_value ^ xor_value
   # rol     eax, VALUE
   calculated_value = rol(calculated_value, rol_value, 32)
   return calculated_value


def analyze_mov_obfuscation(func) -> int:
   """
   pattern:
   {
      mov     eax, VALUE
      pushf
      not     eax
      add     eax, VALUE
      xor     eax, VALUE
      rol     eax, VALUE
      popf
   }
   """
   deobfuscated_movs = 0
   print("[+] Analyzing MOV Obfuscation...")
   print(f"Selected function start_address: 0x{func.start_ea:x}, end_address: 0x{func.end_ea:x}")
   # Get function start address
   current_address = func.start_ea
   while current_address < func.end_ea:
      instruction = idautils.DecodeInstruction(current_address)
      if not instruction:
         break
       
      if instruction.itype == idaapi.NN_mov:
         # Check if the next opcode is pushf
         next_instruction = idautils.DecodeInstruction(current_address + instruction.size)
         if next_instruction.itype == idaapi.NN_pushf:
            print("[+] MOV Obfuscation pattern found!")
            calculated_value = 0
            add_value = xor_value = rol_value = 0
            # Get value from {mov eax, VALUE} and MASK for 32bit
            initial_value = instruction.ops[1].value & MASK
            # Add current_address and mov and pushf
            current_address += instruction.size + next_instruction.size
            while True:
               current_instruction = idautils.DecodeInstruction(current_address)
               if current_instruction.itype == idaapi.NN_not:
                  current_address += current_instruction.size
               elif current_instruction.itype == idaapi.NN_add:
                  add_value = current_instruction.ops[1].value & MASK
                  current_address += current_instruction.size
               elif current_instruction.itype == idaapi.NN_xor:
                  xor_value = current_instruction.ops[1].value & MASK
                  current_address += current_instruction.size 
               elif current_instruction.itype == idaapi.NN_rol:
                  rol_value = current_instruction.ops[1].value & MASK
                  current_address += current_instruction.size
               elif current_instruction.itype == idaapi.NN_popf:
                  calculated_value = calculate_mov_value(
                     init_value=initial_value,
                     add_value=add_value,
                     xor_value=xor_value,
                     rol_value=rol_value
                  )
                  current_address += current_instruction.size
               elif current_instruction.itype == idaapi.NN_pushf:
                  # The pattern we are looking for can be repetitive,
                  # so we need to keep the process going.
                  initial_value = calculated_value
                  current_address += current_instruction.size
               else:
                  break
            print(f"[+] Calculated MOV value: {hex(calculated_value)}")
            deobfuscated_movs += 1
         else:
            current_address += instruction.size
      else:
         current_address += instruction.size
   
   return deobfuscated_movs

def main():
   print("[~] 0xReverse - Alcatraz Deobfuscator IDA Script [~]")
   # Select a mutated function on IDA Screen
   start_address = idaapi.get_screen_ea()
   if selected_function := ida_funcs.get_func(start_address):
      function_name = idc.get_func_name(start_address)
      print(f"[+] Analyzing Function Name: {function_name}, Address: {start_address:x}")
      deobfuscated_mov_ops = analyze_mov_obfuscation(func=selected_function)
      print(f"[+] Deobfuscated {deobfuscated_mov_ops} MOV obfuscation")
   else:
        print(f"[-] This address is not a function")
        exit(-1)

main()