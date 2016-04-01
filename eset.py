import sys
import idaapi
from idaapi import *

fixed_value = 0x0;

def vm_get_data_reg_imm(vmctx, type, reg_index, size):
        global  fixed_value;
        
        if type == 1:
                if size == 1:
                        return o_phrase, dt_word, reg_index;
                elif size == 2:
                        return o_phrase, dt_dword, reg_index;
                else:
                        return o_phrase, dt_byte, reg_index;
                
        elif type == 2:
                if size == 1:
                        return o_imm, dt_word, ua_next_word();
                elif size == 2:
                        return o_imm, dt_dword, ua_next_long();
                else:
                        return o_imm, dt_byte, ua_next_byte();
        elif type == 3:
                return o_imm, dt_dword, ua_next_long() + fixed_value;
        else: # type == 0:
                if size == 1:
                        return o_reg, dt_word, reg_index;
                elif size == 2:        
                        return o_reg, dt_dword, reg_index;
                else:
                        return o_reg, dt_byte, reg_index;
    
#no need for value as 4th argument, as this is not needed...
def vm_store_imm_to_vmreg(vmctx, type, size, reg_index):
        if type == 0:
                return o_reg, dt_dword, reg_index;
        else:
                if size == 1:
                        return o_phrase, dt_word, reg_index;
                elif size == 2:
                        return o_phrase, dt_dword, reg_index;
                else:
                        return o_phrase, dt_byte, reg_index; 

# ----------------------------------------------------------------------
class sample_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['esetcrk']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['EsEtCrAcKmE_VM']  

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    regFirstSreg = 16 # index of CS
    regLastSreg = 16 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    regCodeSreg = 16
    regDataSreg = 17

    # icode of the first instruction
    instruc_start = 0

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 1

    # If the FIXUP_VHIGH and FIXUP_VLOW fixup types are supported
    # then the number of bits in the HIGH part. For example,
    # SPARC will have here 22 because it has HIGH22 and LOW10 relocations.
    # See also: the description of PR_FULL_HIFXP bit
    # (optional)
    high_fixup_bits = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # array of unsupported instructions (array of cmd.itype) (optional)
        'badworks': [6, 11],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 3-byte data (optional)
        'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler
                
    # Array of instructions
    instruc = [               
        {'name': 'push',           'feature': CF_USE1},
        {'name': 'pop',            'feature': CF_USE1 | CF_CHG1},
        {'name': 'sub',            'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'add',            'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'mov',            'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'ret',            'feature': CF_STOP},
        {'name': 'end'  ,          'feature': CF_STOP},
        {'name': 'call',           'feature': CF_CALL | CF_USE1},
        {'name': 'jmp_cc',         'feature': CF_USE1},
        {'name': 'jmp',            'feature': CF_USE1},
        {'name': 'xor'  ,          'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'stop',           'feature': CF_STOP},
        {'name': 'vm_alloc',       'feature': CF_USE1},
        {'name': 'vm_free',        'feature': CF_USE1},
        {'name': 'cmpeq',          'feature': CF_USE1 | CF_USE2},
        {'name': 'cmple',          'feature': CF_USE1 | CF_USE2},
        {'name': 'cmpne',          'feature': CF_USE1 | CF_USE2},
        {'name': 'rol8',           'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'ror8',           'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'rol16',          'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'ror16',          'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'rol32',          'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'ror32',          'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'shr',            'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'shl',            'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'mod',            'feature': CF_USE1 | CF_CHG1 | CF_USE2},
        {'name': 'call_func',      'feature': CF_USE1},
        {'name': 'call_func_hash', 'feature': CF_USE1 | CF_USE2},
        {'name': 'run_vm',         'feature': CF_USE1 | CF_USE2},
    ];
    
       
                            
    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1
    # register names
    regNames = ["r%d" % i for i in range(0, 64/4)];
    regNames.append("CS");
    regNames.append("DS");
    
    # number of registers (optional: deduced from the len(regNames))
    regsNum = len(regNames)
    
                            
    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #
    
    def __init__(self):
        processor_t.__init__(self);
        self.ins = {};                       #build dictionary...
        self.regs = ["r%d" % i for i in range(0, 64/4)];
        
        #for idx, i in enumerate(self.instruc):     #enumerate everything with index
        for idx, i in enumerate(self.instruc):
                self.ins[i["name"]] = idx;      #asign index to every instruction...
                
        
        #custom needed fields... which are different for kernel
        #and user mode... for kernel we have
        #sig <size><eip><needed><kernel_user>
        #for user we have... 
        #sig <eip> <needed><size><kernel_user>
        #because of this code has to be setup differently...
        
          
    def _emu_operand(self, op):
        #if o_near calculate next code reference and add next code reference
        if op.type == o_near:
                if self.cmd.get_canon_feature() & CF_CALL:
                        fl = fl_CN;
                else:
                        fl = fl_JN;
                ua_add_cref(0, op.addr, fl); 
        if op.type == o_mem:
                #ua_add_off_drefs(op, dr_R);
                ua_dodata2(0, op.addr, op.dtyp); 
                ua_add_dref(0, op.addr, op.dtyp);       
    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        feature = cmd.get_canon_feature();
        if feature & CF_USE1: self._emu_operand(cmd[0]);
        if feature & CF_USE2: self._emu_operand(cmd[1]);
        if feature & CF_USE3: self._emu_operand(cmd[2]);
        #if feature & CF_STOP return True;
        if feature & CF_STOP:
                return True;
        #if not feature & CF_CALL:
        #pass flow to next instruction
        ua_add_cref(0, cmd.ea + cmd.size, fl_F);
        
        return True;

    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        
        if op.type == o_reg:
                if op.dtyp == dt_byte:
                        out_register(self.regs[op.reg] + "b");
                elif op.dtyp == dt_word:
                        out_register(self.regs[op.reg] + "w");
                else:
                        out_register(self.regs[op.reg]);
        elif op.type == o_imm:
                OutValue(op, OOFW_IMM);     
        elif op.type == o_near:
            r = out_name_expr(op, op.addr, BADADDR)        
        elif op.type == o_phrase:
                if op.dtyp == dt_byte:
                        out_register("byte ");
                elif op.dtyp == dt_word:
                        out_register("word ");
                else:
                        out_register("dword ");
                out_symbol('[')
                out_register(self.regs[op.reg])
                out_symbol(']')
        elif op.type == o_mem:
                r = out_name_expr(op, op.addr, BADADDR);
                if not r:
                        out_symbol("[");
                        OutLong(op.addr, 16);
                        out_symbol("]");
                
                
        else:
                return False;
        return True

    def out(self):   
        
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        feature = cmd.get_canon_feature();
        
        buff = idaapi.init_output_buffer(1024);
        OutMnem(12);
        
        if feature & CF_USE1:
                out_one_operand(0);
        if feature & CF_USE2:
                OutChar(",");
                OutChar(" ");
                out_one_operand(1);
        if feature & CF_USE3:
                OutChar(",");
                OutChar(" ");
                out_one_operand(2);
        term_output_buffer();
        cvar.gl_comm = 1;
        MakeLine(buff);
        
    def ana(self):
        self.vm_opcode_base = 0x12;
        global fixed_value;
        
        self.kernel_user = idaapi.get_long(0xE);
        self.vm_eip      = 0;
        if self.kernel_user == 1:
                self.vm_eip = idaapi.get_long(0x6);
                fixed_value = idaapi.get_long(0xA);
        else:
                self.vm_eip = idaapi.get_long(0x2);
                fixed_value = idaapi.get_long(0x6);        
                
        self.vm_tmp = idaapi.get_word(0);
        if self.vm_tmp == 0x3731:
                self.vm_opcode_base = self.vm_eip;
        if self.vm_tmp == 0x1337:
                self.vm_opcode_base = self.vm_eip; 
                
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """
        b = ua_next_byte();
        
        if b == 00:
                cmd.itype = self.ins["stop"];
        elif b == 01:
                cmd.itype = self.ins["mov"];
                b0 = ua_next_byte();
                b1 = ua_next_byte();
                
                type, dtyp, data = vm_store_imm_to_vmreg(0, (b1 >> 2) & 3, (b1 >> 4) & 3, b0 & 0xF);
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                cmd[0].reg  = data;
                                
                type, dtyp, data = vm_get_data_reg_imm(0, b1 & 3, (b0 >> 4) & 0xf, (b1 >> 4) & 3);
                cmd[1].type = type;
                cmd[1].dtyp = dtyp;
                if type == o_reg:
                        cmd[1].reg = data;
                elif type == o_imm:
                        cmd[1].value = data;
                else:
                        cmd[1].reg = data;
                                           
        elif b == 02:
                b0 = ua_next_byte();
                type, dtyp, data = vm_get_data_reg_imm(0, (b0 >> 4) & 3, b0 & 0xF, 2);
                
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                if type == o_reg:
                        cmd[0].reg = data;
                elif type == o_imm:
                        cmd[0].value = data;
                else:
                        cmd[0].reg = data;
                
                cmd.itype = self.ins["call_func"];
        elif b == 03:
                cmd.itype = self.ins["call_func_hash"];
                
                b0 = ua_next_byte();
                b1 = ua_next_byte();
                
                mem_disp = b1 & 3;
                
                type, dtyp, data = vm_get_data_reg_imm(0, b1 & 3, b0 & 0xF, 2);
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                if type == o_reg:
                        cmd[0].reg = data;
                elif type == o_imm:
                        cmd[0].value = data;
                else:
                        cmd[0].reg = data;
                
                if mem_disp ==  3 and cmd[0].type != o_phrase:
                        cmd[0].type = o_mem;
                        cmd[0].dtyp = dt_dword;
                        cmd[0].addr = data;
                 
                
                type, dtyp, data = vm_get_data_reg_imm(0, (b1>>2)&3, (b0>>4)&0xF, 2);
                cmd[1].type = type;
                cmd[1].dtyp = dtyp;
                if type == o_reg:
                        cmd[1].reg = data;
                elif type == o_imm:
                        cmd[1].value = data;
                else:
                        cmd[1].reg = data;       
                        
                mem_disp = (b1 >> 2) & 3;
                if mem_disp ==  3 and cmd[1].type != o_phrase:
                        cmd[1].type = o_mem;
                        cmd[1].dtyp = dt_dword;
                        cmd[1].addr = data;        
                
        elif b == 04:
                cmd.itype = self.ins["push"];
                b0 = ua_next_byte();
                type, dtyp, data = vm_get_data_reg_imm(0, (b0>>4)&3, b0 & 0xF, (b0 >> 6) & 0xF);
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                if type == o_reg:
                        cmd[0].reg = data;
                elif type == o_imm:
                        cmd[0].value = data;
                else:
                        cmd[0].reg = data;
                         
        elif b == 05:
                cmd.itype = self.ins["pop"];
                b0 = ua_next_byte();
                cmd[0].type = o_reg;
                cmd[0].dtyp = dt_dword;
                cmd[0].reg  = b0 & 0xF;
        elif b == 6:
                b0 = ua_next_byte();
                b1 = ua_next_byte();
                type, dtyp, data = vm_get_data_reg_imm(0, (b1 & 3), (b0>>4)&0xF, (b1 >> 2)&3);
                cmdtype = (b1 >> 4) & 7
                regidx  = b0 & 0xF;
                
                cmd[1].type = type;
                cmd[1].dtyp = dtyp;
                if type == o_reg:
                        cmd[1].reg = data;
                elif type == o_imm:
                        cmd[1].value = data;
                else:
                        cmd[1].reg = data;
                        
                cmd[0].type = o_reg;
                cmd[0].dtyp = dt_dword;
                cmd[0].reg  = regidx;
                
                if cmdtype == 1:
                        cmd.itype = self.ins["cmpne"];
                elif cmdtype == 2:
                        cmd.itype = self.ins["cmple"];
                else:
                        cmd.itype = self.ins["cmpeq"];                
        elif b == 7:
                b0 = ua_next_byte();
                if b0 == 1:
                        cmd.itype = self.ins["jmp_cc"];
                else:
                        cmd.itype = self.ins["jmp"];
                        
                type, dtyp, data = vm_get_data_reg_imm(0, 2, 0, 2);
                cmd[0].type = o_near; #type;
                cmd[0].dtyp = dt_dword; #dtyp;
                cmd[0].addr = data + self.vm_opcode_base;
                #if data == o_reg:
                #        cmd[0].reg = data;
                #elif data == o_imm:
                #        cmd[0].value = data;
                #else:
                #        cmd[0].reg = data; 
        
        elif b == 8:
                cmd.itype = self.ins["call"];
                type, dtyp, data = vm_get_data_reg_imm(0, 2, 0, 2);
                cmd[0].type = o_near;
                cmd[0].dtyp = dt_dword;
                cmd[0].addr = data + self.vm_opcode_base;                
        elif b == 9:
                cmd.itype = self.ins["ret"];           
        elif b == 10:
                b0 = ua_next_byte();
                b1 = ua_next_byte();
                
                cmdtype = (b1 >> 4) & 7;
                type, dtyp, data = vm_get_data_reg_imm(0, b1 & 3, (b0>>4)&0xF, (b1>>2) & 3);
                cmd[1].type = type;
                cmd[1].dtyp = dtyp;
                if type == o_reg:
                        cmd[1].reg = data;
                elif type == o_imm:
                        cmd[1].value = data;
                else:
                        cmd[1].reg = data;
                
                cmd[0].type = o_reg;
                cmd[0].dtyp = dt_dword;
                cmd[0].reg  = b0 & 0xF;
                
                opsize = (b1 >> 2) & 3;
                
                if cmdtype == 1:
                        cmd.itype = self.ins["add"];
                elif cmdtype == 2:
                        cmd.itype = self.ins["sub"];
                elif cmdtype == 3:
                        cmd.itype = self.ins["shl"];        
                elif cmdtype == 4:
                        cmd.itype = self.ins["shr"];
                elif cmdtype == 5:
                        #rol or ror
                        if opsize == 1:
                                cmd.itype = self.ins["rol16"];
                        elif opsize == 2:
                                cmd.itype = self.ins["rol32"];
                        else:
                                cmd.itype = self.ins["rol8"];
                elif cmdtype == 6:
                        #rol or ror
                        if opsize == 1:
                                cmd.itype = self.ins["ror16"];
                        elif opsize == 2:
                                cmd.itype = self.ins["ror32"];
                        else:
                                cmd.itype = self.ins["ror8"];
                elif cmdtype == 7:
                        cmd.itype = self.ins["mod"];
                else:
                        cmd.itype = self.ins["xor"];
        elif b == 11:
                cmd.itype = self.ins["vm_alloc"];
                b0 = ua_next_byte();
                type, dtyp, data = vm_get_data_reg_imm(0, (b0 >> 4) & 3, b0 & 0xF, (b0>>6) & 0xF);
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                if type == o_reg:
                        cmd[0].reg = data;
                elif type == o_imm:
                        cmd[0].value = data;
                else:
                        cmd[0].reg = data;
        elif b == 12:
                cmd.itype = self.ins["vm_free"];
                b0 = ua_next_byte();
                type, dtyp, data = vm_get_data_reg_imm(0, (b0 >> 4) & 3, b0 & 0xF, (b0>>6) & 0xF);
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                if type == o_reg:
                        cmd[0].reg = data;
                elif type == o_imm:
                        cmd[0].value = data;
                else:
                        cmd[0].reg = data;
                        
        elif b == 13:
                cmd.itype = self.ins["run_vm"];
                b0 = ua_next_byte();
                b1 = ua_next_byte();
                type, dtyp, data = vm_get_data_reg_imm(0, b1 & 3, b0 & 0xF, 2);
                cmd[0].type = type;
                cmd[0].dtyp = dtyp;
                if type == o_reg:
                        cmd[0].reg = data;
                elif type == o_imm:
                        cmd[0].value = data;
                else:
                        cmd[0].reg = data;
                type, dtyp, data = vm_get_data_reg_imm(0, (b1 >> 2) & 3, (b0 >> 4) & 0xF, (b1 >> 4) & 3);
                cmd[1].type = type;
                cmd[1].dtyp = dtyp;
                if type == o_reg:
                        cmd[1].reg = data;
                elif type == o_imm:
                        cmd[1].value = data;
                else:
                        cmd[1].reg = data;                                        
        else:
                #print("opcode : %d" % b);
                #cmd.itype = self.ins["stop"];               
                return 0;
        
        # Return decoded instruction size or zero
        return self.cmd.size

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return sample_processor_t()
