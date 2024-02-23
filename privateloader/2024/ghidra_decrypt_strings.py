import numpy as np
import struct
import string
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.address import AddressSet

def comment_string(dec_string, addr):
    codeUnit = currentProgram().getListing().getCodeUnitAt(addr)
    codeUnit.setComment(codeUnit.PRE_COMMENT, ''.join(filter(lambda x: x in set(string.printable), dec_string)))

# Recursive function to search for encrypted strings in the assembly code
def search_for_encrypted_strings(instruction, str_len, start_address, key):
    program = currentProgram()
    bytes_found = dict()
    str_addr = start_address
    
    while len(b''.join(bytes_found.values())) < str_len + 2:
        instruction = instruction.getPrevious()
        
        function = program.getListing().getFunctionAt(instruction.getAddress())
        if function and function.getEntryPoint() == instruction.getAddress():
            # If the previous instruction is the start of a function, recursively search for strings
            refs = program.getReferenceManager().getReferencesTo(function.getEntryPoint())
            for ref in refs:
                ref_address = ref.getFromAddress()
                instruction = program.getListing().getInstructionAt(ref_address)
                if instruction:
                    search_for_encrypted_strings(instruction, str_len, ref_address, key)
            return
        
        elif instruction.getMnemonicString() == 'MOV':
            if instruction.getOpObjects(1)[0].getClass() == Scalar:
                value = instruction.getOpObjects(1)[0].getValue()
                
                # Find data offset
                offset = -1
                for obj in instruction.getOpObjects(0):
                    if obj.getClass() == Scalar:
                        offset = obj.getValue()
                        break
                
                if str(instruction).startswith('MOV byte'):
                    bytes_found[offset] = struct.pack('B', value) 
                elif str(instruction).startswith('MOV word'):
                    bytes_found[offset] = struct.pack('<H', value) 
                elif str(instruction).startswith('MOV dword'):
                    bytes_found[offset] = struct.pack('<I', value) 
                elif str(instruction).startswith('MOV qword'):
                    bytes_found[offset] = struct.pack('<Q', value)
                    
        elif instruction.getMnemonicString() in ['MOVDQU', 'MOVUPS']:
            src_register = instruction.getOpObjects(1)[0]
            
            # Find data offset
            offset = -1
            for obj in instruction.getOpObjects(0):
                if obj.getClass() == Scalar:
                    offset = obj.getValue()
                    break
            
            # Find the instruction where the register was previously moved from the data section
            prev_instruction = instruction
            data_bytes = None
            while not data_bytes:
                prev_instruction = prev_instruction.getPrevious()
                if prev_instruction and prev_instruction.getMnemonicString() in ['MOVDQA', 'MOVAPS']:
                    dest_register = prev_instruction.getOpObjects(0)[0]
                    # Check if the source register matches the destination register
                    if dest_register == src_register:
                        # Extract the data from the memory location specified in the instruction
                        data_address = prev_instruction.getAddress(1)
                        data_bytes = np.array(getBytes(data_address, 16), dtype=np.byte).tobytes()
            
            bytes_found[offset] = data_bytes
    
    if bytes_found:
        # Order bytes found by offset
        encrypted_string = b''.join([bytes_found[key] for key in sorted(bytes_found.keys())])
        
        # Decrypt string
        decrypted_string = ''
        for i, b in enumerate(encrypted_string[:-2]):
            decrypted_string += chr((b ^ (i + key) & 0xff))
        
        # Add a comment to the address with the decrypted string
        comment_string(decrypted_string, str_addr)
        print("{} {}".format(str_addr, decrypted_string))
        
def search_sequence(sequence):
    # Get the current program in Ghidra
    program = currentProgram()

    # Get the start and end addresses of the .text section
    text_section = program.getMemory().getBlock('.text')
    start = text_section.getStart()
    end = text_section.getEnd()

    # Get the listing for the current program
    listing = program.getListing()

    # Initialize the iterator to iterate through code units (instructions) in the specified address range
    codeUnitIterator = listing.getCodeUnits(AddressSet(start, end), True)

    # Initialize variables to keep track of the current position in the sequence
    current_position = 0
    sequence_address = None  # Variable to store the potential sequence address
    
    sequence_addresses = []

    # Iterate through code units
    while codeUnitIterator.hasNext():
        codeUnit = codeUnitIterator.next()

        # Check if the current instruction mnemonic matches the expected mnemonic in the sequence
        if codeUnit.getMnemonicString() == sequence[current_position]:
            if current_position == 0:
                # Save the potential sequence address on the first mnemonic match
                sequence_address = codeUnit.getAddress()
            current_position += 1
        else:
            current_position = 0
            sequence_address = None  # Reset potential sequence address if the sequence is not matched

        # If the entire sequence is found, add the potential sequence address to the list of found addresses
        if current_position == len(sequence):
            sequence_addresses.append(sequence_address)   
            current_position = 0  # Reset current position for potential future matches
            sequence_address = None  # Reset potential sequence address for potential future matches
    
    return sequence_addresses
            
def search_for_strings(start_address):
    # Get the instruction at the found address
    instruction = currentProgram().getListing().getInstructionAt(start_address)

    # Extract key and string length from the instructions
    try:
        key = instruction.getOpObjects(1)[1].getValue()
    except:
        instruction = instruction.getNext()
        key = instruction.getOpObjects(1)[1].getValue()
        
    cmp_inst = instruction.getNext().getNext().getNext()
    str_len = cmp_inst.getOpObjects(1)[0].getValue()
    
    search_for_encrypted_strings(instruction, str_len, start_address, key)
            
if __name__ == "__main__":
            
    loop_sequece_1 = ['LEA', 'XOR', 'INC', 'CMP', 'JC']
    loop_sequece_2 = ['LEA', 'LEA', 'INC', 'XOR', 'CMP', 'JC']
    loop_addresses = search_sequence(loop_sequece_1) + search_sequence(loop_sequece_2)
    
    for addr in loop_addresses:
        try:
            search_for_strings(addr)
        except Exception as e:
            print("{} {}".format(addr, str(e)))