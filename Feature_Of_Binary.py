# encoding:utf-8
# time 2017:8:21  15:37
# author ysg
# function : extract features from executable binary file
from idautils import *
from idaapi import *
from idc import *
import copy
import sys, os
OPTYPEOFFSET = 1000

# user defined op type
o_string = o_imm + OPTYPEOFFSET
o_calls = OPTYPEOFFSET + 100
o_trans = OPTYPEOFFSET + 101 # Transfer instructions
o_arith = OPTYPEOFFSET + 102 #arithmetic instructions
# 将当前路径添加入搜索路径
sys.path.append(os.getcwd())
#
transfer_instructions = ['MOV','PUSH','POP','XCHG','IN','OUT','XLAT','LEA','LDS','LES','LAHF', 'SAHF' ,'PUSHF', 'POPF']
arithmetic_instructions = ['ADD', 'SUB', 'MUL', 'DIV', 'XOR', 'INC','DEC', 'IMUL', 'IDIV']
# is_type_arithmetic()
from LogRecorder import CLogRecoder

logger = CLogRecoder(logfile='test.log')
logger.addStreamHandler()
logger.INFO("\n---------------------\n")


class Attributes_BlockLevel(object):
    def __init__(self, func_t):
        self._Blocks = set()
        self._Blocks_list = []
        self._func = func_t
        self._block_boundary = {}
        self._addr_func = func_t.startEA  # first address of function
        self._name_func = str(GetFunctionName(func_t.startEA))  # GetFunctionName(startEA) returns the function name
        self._All_Calls = []
        self._CFG = {} # key : Block startEA ; value : Block startEA of successors
        self._init_all_nodes()

        self._Betweenness = {}
        self._djstra()

        #print betweenness
        # for key in self._Betweenness:
        #     logger.INFO(hex(key) + str(self._Betweenness[key]))


    #get Betweenness
    def _djstra(self):
        self._Betweenness[self._addr_func] = 0 #首节点加入
        added_node_set = set()
        added_node_set.add(self._addr_func)
        #记录其前驱节点
        pre = {}
        for node in self._Blocks:
            pre[node] = []
        logger.INFO('in %s djstra running ...' % GetFunctionName(self._func.startEA))
        while True:
            not_add_node = set(self._Blocks_list) - added_node_set
            if len(not_add_node) == 0:
                break

            logger.INFO('added_node : ' + str(added_node_set))
            logger.INFO('not added nodes' + str(not_add_node))
            logger.INFO('CFG' + str(self._CFG))
            for added_node in copy.deepcopy(added_node_set):
                for node in not_add_node:
                    if node in self._CFG[added_node]:
                        # added_node 以及其前驱节点加1
                        self._Betweenness[node] = 0
                        self._update_betweenness(added_node, pre)
                        pre[node].append(added_node)
                        added_node_set.add(node)
                        # logger.INFO('node '+ hex(node) + ' , pre_node ' + hex(added_node))
        self._Betweenness[self._Blocks_list[0]] = 0
        logger.INFO('djstra finished ...')

    def _update_betweenness(self, added_node, pre):
        self._Betweenness[added_node] += 1
        if len(pre[added_node]) == 0:
            return
        for pre_node in pre[added_node]:
            self._update_betweenness(pre_node, pre)


    # initial block_boundary , get every node's range of address
    def _init_all_nodes(self):
        flowchart = FlowChart(self._func)
        for i in range(flowchart.size):
            basicblock = flowchart.__getitem__(i)
            self._Blocks.add(basicblock.startEA)
            self._CFG[basicblock.startEA] = [b.startEA for b in basicblock.succs()]
            self._block_boundary[basicblock.startEA] = basicblock.endEA
        self._Blocks_list = list(self._Blocks)
        self._Blocks_list.sort()
        #print CFG
        # for key in self._CFG:
        #     succ = [hex(node) for node in self._CFG[key]]
        #     logger.INFO('node : '+hex(key) + ' succ :' + str(succ))


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

    #offspring means children nodes in CFG
    def get_Offspring_of_Block(self, startEA):
        if startEA not in self._Blocks_list:
            return None
        return len(self._CFG[startEA])


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

    def get_Trans_of_block(self, ea):
        return len(self.get_OpValue_Block(ea, o_trans))

    # startEA:basicblock's start address
    # return all instruction in one block
    # it is replaced by function get_reference_data_one_block
    def get_All_instr_in_one_block(self, startEA):

        return list(self.get_reference_data_one_block(startEA))

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

    def get_Arithmetics_Of_Block(self, ea):
        return len(self.get_OpValue_Block(ea, o_arith))

    # return all function or api names called by this function
    def get_Calls_BLock(self, ea):
        return len(self.get_OpValue_Block(ea, o_calls))
        # ref = xrefblk_t()
        #
        # for ea in self._Blocks_list:
        #     it = func_item_iterator_t(self._func, ea)
        #
        #     while it.next_code():
        #         nea = it.current()
        #         logger.INFO('address :' + hex(nea))
        #         frm = [hex(x.frm) for x in XrefsFrom(nea)]
        #         logger.INFO(str(frm))

    # this is an abstract interface
    # it can replace functions like get_Numeric_Constant
    def get_OpValue(self, ea, my_op_type = o_void):
        OV = []

        # instruction level features
        if (my_op_type == o_trans):
            #it's a transfer instruction if data transfered between reg and mem
            # logger.INFO('disasm:' + GetDisasm(ea))
            inst = GetDisasm(ea).split(' ')[0].upper()
            if (inst in transfer_instructions):
                # logger.INFO('in trans')
                OV.append(inst)
            return OV

        elif( my_op_type == o_arith):
            inst = GetDisasm(ea).split(' ')[0].upper()
            # logger.INFO('disasm:' + GetDisasm(ea))
            if (inst in arithmetic_instructions):
                # logger.INFO('in arithmetic')
                OV.append(inst)
            return OV

        op = 0
        op_type = GetOpType(ea, op)
        while (op_type != o_void):

            #o_calls
            if (my_op_type == o_calls):
                # logger.INFO("disasm : " + GetDisasm(ea))
                if (GetDisasm(ea).split(' ')[0].upper() == "CALL"):
                    # logger.INFO('in o_calls : ' + self.get_instruction(ea))
                    OV.append(GetDisasm(ea).split(' ')[-1])
                    break

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

    #get Betweenness of Blocks
    def get_Betweenness_of_Block(self, startEA):
        if startEA not in self._Betweenness:
            return None
        return self._Betweenness[startEA]

    def get_CFG(self):
        return self._CFG
    '''
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
    '''

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

#get block attributes
# return a dic
# which have keys : startEA, String_Constant, Numberic_Constant, No_Tran, No_Call, No_Instru, No_Arith, No_offspring, Betweenness
def get_att_block(blockEA, Attribute_Block):
    AB = Attribute_Block
    dic = {}
    dic['startEA'] = blockEA
    dic['String_Constant'] = AB.get_All_Strings_of_Block(blockEA)
    dic['Numberic_Constant'] = AB.get_Numeric_Constants_One_block(blockEA)
    dic['No_Tran'] = AB.get_Trans_of_block(blockEA)
    dic['No_Call'] = AB.get_Calls_BLock(blockEA)
    dic['No_Instru'] = len(AB.get_All_instr_in_one_block(blockEA))
    dic['No_Arith'] = AB.get_Arithmetics_Of_Block(blockEA)
    dic['No_offspring'] = AB.get_Offspring_of_Block(blockEA)
    dic['Betweenness'] = AB.get_Betweenness_of_Block(blockEA)
    return dic

def save_Json(filename):

    for i in range(0, get_func_qty()):
        fun = getn_func(i)
        segname = get_segm_name(fun.startEA)
        if segname[1:3] not in ["OA", "OM", "te"]:
            continue
        if (GetFunctionName(fun.startEA) == 'main'):
            continue
        with open(filename, 'a') as f:
            AB = Attributes_BlockLevel(fun)
            logger.INFO(AB.getFuncName())
            CFG = AB.get_CFG()
            dic = {}
            dic['fun_name'] = AB.getFuncName()
            for ea in CFG:
                dic[ea] = get_att_block(ea, AB)
                dic[ea]['succ'] = []
                for succ_ea in CFG[ea]:
                    dic[ea]['succ'].append(get_att_block(succ_ea, AB))
            logger.INFO('dic' + str(dic))
            json.dump(dic, f, indent=4)
            f.write('\n')



def main():

    save_Json('nbsmtp.json')
    return

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
        # print p_func.getCFG_OF_Func()
        # print p_func.getAll_Nodes_Addr()
        # for item in p_func.getAll_Nodes_Addr():
        # print hex(item),hex(p_func.get_Nodes_Endaddr(item))
        if (GetFunctionName(fun.startEA) != 'main'):
            p_func = Attributes_BlockLevel(fun)
            logger.INFO(p_func.getFuncName())
            # p_func.get_All_Calls()
            allnodes = p_func.get_All_Nodes_StartAddr()
            for ea in allnodes:
                logger.INFO('block start' + hex(ea))
                logger.INFO('block offspring:' + str(p_func.get_Offspring_of_Block(ea)))
                logger.INFO('block betweenness :' + str(p_func.get_Betweenness_of_Block(ea)))
                # logger.INFO('block instructions :' + str(len(p_func.get_All_instr_in_one_block(ea))))
                # logger.INFO(p_func.get_reference_data_one_block(ea).next())
                # logger.INFO('String: ' + str(p_func.get_All_Strings_of_Block(ea)))
                # logger.INFO(p_func.get_Numeric_Constants_One_block(ea))
                # calls = p_func.get_Calls_BLock(ea)
                # logger.INFO(calls)
                # logger.INFO('trans number: ' + str(p_func.get_Trans_of_block(ea)))
                # logger.INFO('arithmetics :' + str(p_func.get_Arithmetics_Of_Block(ea)))

# do something within one function
import json
if __name__ == '__main__':
    main()

    idc.Exit(0)
