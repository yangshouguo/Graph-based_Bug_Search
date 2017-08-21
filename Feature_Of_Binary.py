
# time 2017:8:21  15:37
# author ysg
# function : extract features from executable binary file




from idaapi import *
from idc import *
import sys,os

class Process_with_Single_Function(object):
    def __init__(self, func_t):
        self._Blocks = set()
        self._func = func_t
        self._Edges = {}
        self._addr_func = func_t.startEA #first address of function
        self._name_func = str(GetFunctionName(func_t.startEA)) # GetFunctionName(startEA) returns the function name
    
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
        fun_it = func_item_iterator_t(self._func)
        
        addr_current = fun_it.current() #now is the start address of the function
        
        print hex(addr_current)
        
        #fun_it.next_addr() means addr_current+1
        #fun_it.next_head() means start address of every instruction
        #fun_it.next_code() just like next_head()
        #fun_it.next_data() unkown
        
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




    
    def Analyzer(self):
        print 'a'
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
        print p_func.getCFG_OF_Func()
#do something within one function

if __name__ == '__main__':
    main()

    #idc.Exit(0)
