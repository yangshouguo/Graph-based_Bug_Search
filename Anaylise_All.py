#!/usr/bin/env python
# coding=utf-8

from idc import *
from idaapi import *
import idautils
class AnayBinFil(object):
    def __init__(self):
        list = []
    # 得到某一条汇编指令所指向的内存的内容 
    def GetXref_String(self,ea,n):
        if (GetOpType(ea,n) == 2):
            ea = GetOperandValue(ea,n)
        if (not SegName(ea) == '.rodata'):
            addrx = idautils.DataRefsFrom(ea)
            for item in addrx:
                return self.GetXref_String(item,n)
            return idc.Dword(ea)
        return GetString(ea)
        
    
    #get the register's content whose number is i from ea forward search
    def get_content_register(self,ea,i):
        #print hex(ea) , idc.GetDisasm(ea), i

        if (GetOpType(ea,0) == 1 and GetOperandValue(ea,0) == i):# wanted register
            if (ua_mnem (ea) == 'LDR'):
                if (GetOpType(ea,1) == 2):#Optype is Memory Reference
                    return self.GetXref_String(ea,1)
                elif (GetOpType(ea,1) == 4):#Base+index+Displacement
                    if(GetOperandValue(ea,1) == 0): # like  : LDR R3,[R3]
                        return self.get_content_register(PrevHead(ea),i)
                    else:
                        return 
                else :
                    print 'unkown Optype:' ,hex(ea),idc.GetDisasm(ea)
            elif (ua_mnem(ea) == 'MOV'):
                if (GetOpType(ea,1) == 5):
                    return GetOperandValue(ea,1)
                elif (GetOpType(ea,1) == 1):
                    return self.get_content_register(PrevHead(ea),GetOperandValue(ea,1))
                else:
                    print 'unkown OpType:',hex(ea),idc.GetDisasm(ea)
        else:
            return self.get_content_register(PrevHead(ea),i)


    #from a call instruction BackForward search parameter
    def BackForward(self,addr,n):
        Reg_content = []
        #addr = PrevHead(addr)
        i = 0 # register number
        for i in range(n):
            Reg_content.append(self.get_content_register(addr,i))

        return Reg_content


    def Anayl_Func_Call(self, func_name, para_num):
         if func_name == "":
             return
         
         #get start address
         segkind = ['.text' , '.init' ,'.plt'] 
         #startaddr = idc.SegByName('.rodata')
         startaddr = MinEA() 
         #fun_addr = idc.LocByName(func_name)
         # search the address of the pattern text
         while True:
            fun_addr = FindText(startaddr,SEARCH_DOWN, 0, 0, func_name)
            if not (SegName(fun_addr)) in segkind:
                break
            startaddr = NextHead(fun_addr)

         print 'find pattern string addr',hex(fun_addr)

         #byte_str = [hex(y) for y in bytearray(func_name)]
         #print byte_str

         #print hex(fun_addr),idc.GetDisasm(fun_addr)
         
         call_addrs = idautils.DataRefsTo(fun_addr)
         dic = {}
         for item in call_addrs:
             if (not isCode(GetFlags(item))):
                 continue
             #print hex(item),idc.GetDisasm(item)
             para = self.BackForward(item,para_num)
             xref_funname = GetFunctionName(item)
             dic[xref_funname] = para

         return dic

        


def print_help():
    info = 'use this as : idal64/idal -S"Anaylise_All.py \'print1 %s\'" '
    print info

def main():
    #test code
    if (len (idc.ARGV) < 2):
        print_help()
        ana_fun_name = 'version:'
    else:
        ana_fun_name = idc.ARGV[1]#要分析的函数名
    para_num = 3 #参数数量
    ana = AnayBinFil()
    dic = ana.Anayl_Func_Call(ana_fun_name,para_num)
    
    print '在函数中','其调用参数为'
    for item in dic:
        print item , dic[item]
    
    sf = open("out.dat",'w')
    if not sf:
        
        sf.write ('parameter:'+str(idc.ARGV[0])+str(idc.ARGV[1])+'\n')
        idc.Exit(0)
    for item in dic:
        sf.write('In function : '+item+'\n')
        x = (dic[item])
        s = '    '
        for i in range(len(x)):
            if x[i] is None:
                continue
            s += str(x[i])+' , '
        sf.write(s + '\n')
        
    sf.close()
    '''
    # get all names and it's addr
    for x in Names():
        print x
    '''   
    #idc.Exit(0)

if __name__ == '__main__':
    main()
