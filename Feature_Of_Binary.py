
# time 2017:8:21  15:37
# author ysg
# function : extract features from executable binary file




from idaapi import *
from idc import *
import sys,os

class Process_with_Single_Function(object):
    def __init__(self, func_t):
        self._Blocks = set()
        self._Blocks_list = []
        self._func = func_t
        self._block_boundary = {}
        self._addr_func = func_t.startEA #first address of function
        self._name_func = str(GetFunctionName(func_t.startEA)) # GetFunctionName(startEA) returns the function name
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
    # startEA:basicblock's start address
    # return all instruction in one node
    def get_All_instr_in_one_Node(self,startEA):
        instr_list = []
        if (not self._block_boundary.has_key(startEA)):
            return instr_list
        
        endEA = self._block_boundary[startEA]
        it_code = func_item_iterator_t(self._func, startEA)
        ea = it_code.current() 
        while ((ea) < endEA):
            newlist = []
            newlist.append(ua_mnem(ea))
            i = 0
            op = GetOpnd(ea,i)
            while not op == "":
                newlist.append(op)
                i+=1
                op = GetOpnd(ea,i)
                 
                
            instr_list.append(newlist)
            if(not it_code.next_code()):
                break
            ea = it_code.current()

        return instr_list
    
    #return function's name
    def getFuncName(self):
        return self._name_func

    def FrameSize(self):
        return GetFrameSize(self._func.startEA) # get full size of function frame
    
    def getHexAddr(self,addr):
        return hex(addr)
    
    def FrameArgsSize(self): # get size of arguments in function frame which are purged upon return
        return GetFrameArgsSize(self._func.startEA)
    
    def FrameRegsSize(self):# get size of 
        return GetFrameRegsSize(self._func.startEA)

    def getCFG_OF_Func(self):#get the Control Flow Graph of the function , return a list in the form of [(current_block_startaddr:next_block_startaddr), ......]
        # if a function has only one node , it's cfg may be empty
        #flowchart for a function
        
        flowchart = FlowChart(self._func)
        list = []

        for i in range(flowchart.size):
            basicblock = flowchart.__getitem__(i)
            suc = basicblock.succs()
            for item in suc:
                list.append(((basicblock.startEA),(item.startEA)))
            #print basicblock.id,hex(basicblock.startEA),hex(basicblock.endEA)
            
        return list

    # return all the start address of basicblock in form of set
    def getAll_Nodes_Addr(self):
        return self._Blocks_list

    #return a blocks end address
    def get_Nodes_Endaddr(self,startEA):
        if (self._block_boundary.has_key(startEA)):
            return self._block_boundary[startEA]
        return -1

#print how to use this script
def print_help():
    help = 'args not enough'
    print help
def main():
    if len(idc.ARGV) < 0:
        print_help()
        return
    set_seg = set()
    for i in range(0,get_func_qty()):
        fun = getn_func(i) # get_func returns a func_t struct for the function
        segname = get_segm_name(fun.startEA) # get the segment name of the function by address ,x86 arch segment includes (_init _plt _plt_got _text extern _fini)
        if segname[1:3] not in ["OA","OM","te"]:
            continue

        p_func = Process_with_Single_Function(fun)
        print p_func.getFuncName()
        #print p_func.getCFG_OF_Func()
        #print p_func.getAll_Nodes_Addr()
        #for item in p_func.getAll_Nodes_Addr():
            #print hex(item),hex(p_func.get_Nodes_Endaddr(item))
        if (p_func.getFuncName() == 'send_mail'):
            allnodes = p_func.getAll_Nodes_Addr()
            for i in range(len(allnodes)):
                print hex(allnodes[i])
                instr_list = p_func.get_All_instr_in_one_Node(allnodes[i])
                print instr_list



#do something within one function

if __name__ == '__main__':
    main()

    #idc.Exit(0)
