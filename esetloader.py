import idaapi
import struct
from idc import *

# -----------------------------------------------------------------------
def accept_file(li, n):
    if n > 0:
        return 0
    
    return {'format': "EsEtCrAcKmE_VM loader", 'options': 1} # accept the file

    return 0


def myAddSeg(startea, endea, base, use32, name, clas):
    s = idaapi.segment_t()
    s.startEA     = startea
    s.endEA       = endea
    s.sel         = idaapi.setup_selector(base)
    s.bitness     = use32
    s.align       = idaapi.saRelPara
    s.comb        = idaapi.scPub
    idaapi.add_segm_ex(s, name, clas, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_OR_DIE)

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    chunksize = li.size();
    base  = 0x0000
    start = base << 4;
    
    idaapi.set_processor_type("esetcrk", idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)

    # make E and F segments for real-mode part
    myAddSeg(start, start+chunksize, base, 0, "CODE", "CODE")
    li.file2base(0, start, start+chunksize, 1)
    SetSegDefReg(start, "ds", base)

    start_code = idaapi.get_many_bytes(0, 0x14);
    kernel_user = idaapi.get_long(0xE);
    vm_eip      = 0;
    vm_opcode_base = 0x12;
    if kernel_user == 1:
        vm_eip = idaapi.get_long(0x6);
    else:
        vm_eip = idaapi.get_long(0x2);
        fixed_value = idaapi.get_long(0x6);        
                
    vm_tmp = idaapi.get_word(0);
    if vm_tmp == 0x3731:
        vm_opcode_base = vm_eip;
    if vm_tmp == 0x1337:
        vm_opcode_base = vm_eip;  
    	


    # set the entry registers to F000:FFF0
    SetLongPrm(INF_START_IP, vm_opcode_base)
    SetLongPrm(INF_START_CS, 0x0000)    
    # turn off "Convert 32bit instruction operand to offset", too many false positives in high areas
    SetShortPrm(INF_START_AF, GetShortPrm(INF_START_AF) & ~AF_IMMOFF)
    # turn off "Create function tails"
    SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) & ~AF2_FTAIL)

    return 1

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    Warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0
