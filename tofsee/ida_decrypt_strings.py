# adapted from https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c

import idaapi, idc, idautils

class DecryptorError(Exception):
    pass

def decrypt(input_str, key1, key2):
    out = []
    for i in range(len(input_str)):
        out.append(key1 ^ input_str[i])
        if i % 2:
            key1 = (key1 + key2 - 1) & 0xFF
        else:
            key1 = (key1 + key2 + 1) & 0xFF
    return bytes(out)
    
def get_stack_args(fn_addr, count):
    args = []
    found_count = 0
    ptr_addr = fn_addr
    first_push_found = False

    while found_count < count:
        ptr_addr = idc.prev_head(ptr_addr)

        if idc.print_insn_mnem(ptr_addr) == 'push':

            if not first_push_found:
                first_push_found = True
                continue

            operand_type = idc.get_operand_type(ptr_addr, 0)
            if operand_type == idc.o_imm:
                arg = idc.get_operand_value(ptr_addr, 0)
            elif operand_type == idc.o_reg:
                op_val = idc.get_operand_value(ptr_addr, 0)
                reg_name = idaapi.get_reg_name(op_val, 4)
                reg_value = get_reg_value(ptr_addr, reg_name)

                arg = reg_value
            else:
                raise DecryptorError('Not implemented')

            args.append(arg)
            found_count += 1

    if found_count != count:
        raise DecryptorError(f'Only found {found_count} arguments instead of {count}')

    return tuple(args)

def get_reg_value(ptr_addr, reg_name):
    e_count = 0
    while e_count < 500: # go back limit
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    if idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                        return idc.get_operand_value(ptr_addr, 1)
                    else:
                        raise DecryptorError('Not implemented')
                    
        elif idc.print_insn_mnem(ptr_addr) == 'pop':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    while e_count < 500:
                        tmp_addr = idc.prev_head(ptr_addr)
                        if idc.print_insn_mnem(tmp_addr) == 'push':
                            if idc.get_operand_type(tmp_addr, 0) == idc.o_imm:
                                reg_value = idc.get_operand_value(tmp_addr, 0)
                                return reg_value

        elif idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
            raise DecryptorError('Not implemented')
        
    raise DecryptorError('Go back limit reached')

def decrypt_string(call_address):
    try:
        enc_str_ptr, len, key1, key2 = get_stack_args(call_address, 4)
        enc_string = idc.get_bytes(enc_str_ptr, len)
        dec_str = decrypt(enc_string, key1, key2)
        print("0x%x %s" % (call_address, dec_str))
        set_comment(call_address, dec_str.decode())
    except:
        print("0x%x ?" % call_address)
        
def set_hexrays_comment(address, text):
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts()
    
def set_comment(address, text):
    idc.set_cmt(address, text,0) # Set in dissassembly
    set_hexrays_comment(address, text) # Set in decompiled data
        
fn_addr = 0x402544
for xref in idautils.XrefsTo(fn_addr):
    decrypt_string(xref.frm)