# encoding:utf-8
# time 2017:8:21  15:37
# author ysg
# function : extract features from executable binary file
from idautils import *
from idaapi import *
from idc import *
import sys, os
OPTYPEOFFSET = 1000

# user defined op type
o_string = o_imm + OPTYPEOFFSET
# 将当前路径添加入搜索路径
sys.path.append(os.getcwd())

from LogRecorder import CLogRecoder

logger = CLogRecoder(logfile='test.log')
logger.addStreamHandler()
logger.INFO("\n---------------------\n")

class Process_with_Single_Function(object):
    def __init__(self, func_t):
        self._Blocks = set()
        self._Blocks_list = []
        self._func = func_t
        self._block_boundary = {}
        self._addr_func = func_t.startEA  # first address of function
        self._name_func = str(GetFunctionName(func_t.startEA))  # GetFunctionName(startEA) returns the function name
        self._init_all_nodes()

    # initial block_boundary , get every node's range of address
    def _init_all_nodes(self):
        flowchart = FlowChart(self._func)
        for i in range(flowchart.size):
            basicblock = flowchart.__getitem__(i)
            self._Blocks.add(basicblock.startEA)
            self._block_boundary[basicblock.startEA] = basicblock.endEA
        self._Blocks_list = list(self._Blocks)
        self._Blocks_list.sort()

    # # return the n'th operation if it is reference to memory
    # def get_op(self, ea, n, op_type):
    #     # Direct Memory Reference  (DATA)      addr
    #     if (op_type == o_mem):
    #         return GetString(GetOperandValue(ea, n))
    #     elif (op_type == o_phrase):# Memory Ref [Base Reg + Index Reg]    phrase
    #         return GetOperandValue(ea, n)

    '''
    # return the string contained in this instruction
    # if nothing , returns NULL
    # something wrong
    def get_String_in_instruction(self, ea):
        # logger.INFO('ea: ' + hex(ea) + ' inst: '+ GetDisasm(ea))
        All_strings = []
        op = 0
        op_type = GetOpType(ea, op)
        while (op_type != o_void):
            # logger.INFO( 'op: %d, op_type : %d' % (op, op_type))
            if (op_type == o_imm):
                addr = GetOperandValue(ea, op)
                if (not SegName(addr) == '.rodata'):
                    addrx = list(DataRefsFrom(addr))
                    if len(addrx) == 0:
                        op += 1
                        op_type = GetOpType(ea, op)
                        continue
                    addr = addrx[0]
                All_strings.append(GetString(addr))
                # logger.INFO("imm")
                # logger.INFO(GetString(addr))

            op += 1
            try:
                op_type = GetOpType(ea, op)
            except RuntimeError:
                print 'runtime error in', hex(ea), 'op', str(op) ,'OP_TYPE', op_type

        if (len(All_strings) == 0):
            return None

        return All_strings
'''


    # returns all Strings referenced in one block
    # return generator of Strings
    def get_All_Strings_of_Block(self, block_startEA):
        return self.get_OpValue_Block(block_startEA, my_op_type=o_string)


        '''
        All_String = []
        # address is not right
        if (block_startEA not in self._block_boundary):
            return

        strings = []
        endEA = self._block_boundary[block_startEA]
        it_code = func_item_iterator_t(self._func, block_startEA)
        ea = it_code.current()
        while (ea < endEA):
            strings = self.get_String_in_instruction(ea)
            if strings:
                All_String += strings
            # see if arrive end of the blocks
            if (not it_code.next_code()):
                break
            ea = it_code.current()

        return All_String
        '''

    # return a instruction's n'th oprand's reference
    # ea : the address of the instruction
    # n  : order of the operand , 0-the first operand
    def get_reference(self, ea, n):
        if (GetOpType(ea, n) == -1):
            return
        if (GetOpType(ea, n) == 1):
            print
            'General Register'
        if (GetOpType(ea, n) == 2):
            addr = GetOperandValue(ea, n)
            print
            'addr :', hex(Dword(addr))
            print
            ' reference'
            print
            'segment type :', GetSegmentAttr(addr, SEGATTR_TYPE)
            return GetString(Dword(addr))
        elif (GetOpType(ea, n) == 3):
            print
            'base + index'
        elif (GetOpType(ea, n) == 4):
            print
            'B+i+Displacement'
        elif (GetOpType(ea, n) == 5):
            print
            'immediate'
        elif (GetOpType(ea, n) == 6):
            print
            'far address'
        return GetOperandValue(ea, n)

    # there is some error to be solved
    # returns the next address of instruction which are in same basic block
    def get_next_instruction_addr(self, ea):
        return next(ea)

    # get_reference_data_one_block
    def get_reference_data_one_block(self, startEA):

        # address is not right
        if (startEA not in self._block_boundary):
            return

        endEA = self._block_boundary[startEA]
        it_code = func_item_iterator_t(self._func, startEA)
        ea = it_code.current()
        while (ea < endEA):
            yield (''.join(self.get_instruction(ea)))

            # see if arrive end of the blocks
            if (not it_code.next_code()):
                break
            ea = it_code.current()

    # get the whole instruction
    def get_instruction(self, ea):
        return idc.GetDisasm(ea)


    # startEA:basicblock's start address
    # return all instruction in one block
    # it is replaced by function get_reference_data_one_block
    def get_All_instr_in_one_block(self, startEA):

        return self.get_reference_data_one_block(startEA)

        '''
        #
        # instr_list = []
        # if (startEA not in self._block_boundary):
        #     return instr_list
        #
        # endEA = self._block_boundary[startEA]
        # it_code = func_item_iterator_t(self._func, startEA)
        # ea = it_code.current()
        # while ((ea) < endEA):
        #     newlist = []
        #     newlist.append(ua_mnem(ea))
        #     i = 0
        #     op = GetOpnd(ea, i)
        #     while not op == "":
        #         newlist.append(op)
        #         i += 1
        #         op = GetOpnd(ea, i)
        #
        #     instr_list.append(newlist)
        #     if (not it_code.next_code()):
        #         break
        #     ea = it_code.current()
        #
        # return instr_list
        '''

    # return function's name
    def getFuncName(self):
        return self._name_func

    def FrameSize(self):
        return GetFrameSize(self._func.startEA)  # get full size of function frame

    def getHexAddr(self, addr):
        return hex(addr)

    def FrameArgsSize(self):  # get size of arguments in function frame which are purged upon return
        return GetFrameArgsSize(self._func.startEA)

    def FrameRegsSize(self):  # get size of
        return GetFrameRegsSize(self._func.startEA)

    # get operand value in one block
    def get_OpValue_Block(self, startEA, my_op_type):
        OPs = []
        # address is not right
        if (startEA not in self._block_boundary):
            return

        endEA = self._block_boundary[startEA]
        it_code = func_item_iterator_t(self._func, startEA)
        ea = it_code.current()
        while (ea < endEA):
            OPs += self.get_OpValue(ea, my_op_type)
            # see if arrive end of the blocks
            if (not it_code.next_code()):
                break
            ea = it_code.current()

        return OPs

    # this is an abstract interface
    # it can replace functions like get_Numeric_Constant
    def get_OpValue(self, ea, my_op_type = o_void):
        OV = []
        op = 0
        op_type = GetOpType(ea, op)
        while (op_type != o_void):

            if (op_type == my_op_type % OPTYPEOFFSET):
                ov = GetOperandValue(ea, op)
                if (my_op_type == o_imm):
                    if SegName(ov) == "":
                        OV.append(ov)
                elif(my_op_type == o_string):
                    if (not SegName(ov) == '.rodata'):
                        addrx = list(DataRefsFrom(ov))
                        if len(addrx) == 0:
                            op += 1
                            op_type = GetOpType(ea, op)
                            continue
                        ov = addrx[0]
                    OV.append(GetString(ov))

            op += 1
            op_type = GetOpType(ea, op)
        return OV
    '''
    #return the Numeric Constants in the linear address ea
    def get_Numeric_Constants(self, ea):
        # op_enum()
        Con = []
        op = 0
        op_type = GetOpType(ea, op)
        while ( op_type != o_void ):

            if (op_type == o_imm):
                if (SegName(GetOperandValue(ea, op)) == ""):# if the immediate number is not an address
                    Con.append(GetOperandValue(ea, op))

            op += 1
            op_type = GetOpType(ea, op)

        logger.INFO( "get_Numeric_Constants : " + self.get_instruction(ea) +' : '+ str(Con) )
        return Con
    '''

    #get immediate num in blocks
    def get_Numeric_Constants_One_block(self, startEA):
        return self.get_OpValue_Block(startEA, my_op_type=o_imm)


    def getCFG_OF_Func(self):
        # get the Control Flow Graph of the function , return a list in the format of [(current_block_startaddr:next_block_startaddr), ......]
        # if a function has only one node , it's cfg may be empty
        # flowchart for a function

        flowchart = FlowChart(self._func)
        list = []

        for i in range(flowchart.size):
            basicblock = flowchart.__getitem__(i)
            suc = basicblock.succs()
            for item in suc:
                list.append(((basicblock.startEA), (item.startEA)))
                # print basicblock.id,hex(basicblock.startEA),hex(basicblock.endEA)

        return list

    # return all the start address of basicblock in form of set
    def get_All_Nodes_StartAddr(self):
        return self._Blocks_list

    # return a blocks end address
    def get_Block_Endaddr(self, startEA):
        if (startEA in self._block_boundary):
            return self._block_boundary[startEA]
        return -1


# print how to use this script
def print_help():
    help = 'args not enough'
    print(help)


def main():


    if len(idc.ARGV) < 0:
        print_help()
        return
    set_seg = set()
    for i in range(0, get_func_qty()):
        fun = getn_func(i)  # get_func returns a func_t struct for the function
        segname = get_segm_name(
            fun.startEA)  # get the segment name of the function by address ,x86 arch segment includes (_init _plt _plt_got _text extern _fini)
        if segname[1:3] not in ["OA", "OM", "te"]:
            continue

        p_func = Process_with_Single_Function(fun)
        logger.INFO(p_func.getFuncName())
        # print p_func.getCFG_OF_Func()
        # print p_func.getAll_Nodes_Addr()
        # for item in p_func.getAll_Nodes_Addr():
        # print hex(item),hex(p_func.get_Nodes_Endaddr(item))
        if (p_func.getFuncName() == 'main'):
            allnodes = p_func.get_All_Nodes_StartAddr()
            for ea in allnodes:
                logger.INFO('block start' + hex(ea))
                # logger.INFO(p_func.get_reference_data_one_block(ea).next())
                logger.INFO('String: ' + str(p_func.get_All_Strings_of_Block(ea)))
                # logger.INFO(p_func.get_Numeric_Constants_One_block(ea))


# do something within one function

if __name__ == '__main__':
    main()

    idc.Exit(0)
