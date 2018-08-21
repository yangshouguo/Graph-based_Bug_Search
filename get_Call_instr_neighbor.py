#get the instructions nearby call


from idautils import *
from idc import *
from idaapi import *

#get all functions of their address
# return generator
def get_funcs():
	return Functions()

#get the address of the instructions which call the functions
def get_call_instr(addr):
	return [addr for addr in list(CodeRefsTo(addr, 0)) if is_call_insn(addr)]


#get the disasm from start of basic block to given inst_ea
def get_bb_to_ea(inst_ea):
	ea = inst_ea
	func = get_func(inst_ea)
	if not func:
		print 'get wrong address ',hex(inst_ea)
		return []

	inst = []
	#jmp over the call instruction
	inst.append(GetDisasm(ea))
	ea = PrevHead(ea)

	while not is_xref_to(ea) and len(list(XrefsFrom(ea)))>0 and ea > func.startEA:
		inst.append(GetDisasm(ea))
		ea = PrevHead(ea)
		if is_call_insn(ea):
			break

	return list(reversed(inst))

#get the disasm from start of basic block to end of the block
def get_disasm_block(ea):
	func = get_func(ea)
	if not func:
		print 'get wrong address ',hex(ea)
		return []
	inst = []
	while not len(list(CodeRefsFrom(ea, 0)))>0 and ea < func.endEA:
		inst.append(GetDisasm(ea))
		ea = NextHead(ea)
		if is_call_insn(ea):
			break
		# print hex(ea),GetDisasm(ea)

	return inst

def get_Function_name(ea):
	return GetFunctionName(ea)

# if the instruction in ea is refered
def is_xref_to(ea):
	if len(list(CodeRefsTo(ea, 0))) > 0:
		return True

	return False

def main():
	filename = GetInputFile()# file name of binary
	with open(filename+'_directcall.txt','w') as f:
		for func_addr in get_funcs():
			callee_function_name = get_Function_name(func_addr)
			callee_inst = get_disasm_block(func_addr)
			# print('callee_inst' + str(callee_inst))
			for caller_ea in get_call_instr(func_addr):
				caller_inst = get_bb_to_ea(caller_ea)
				caller_function_name = get_Function_name(caller_ea)
				#make sure that 
				if len(callee_inst) >=3 and len(caller_inst) >= 3:
					f.write("\n caller : {} -> callee : {} \n".format(caller_function_name, callee_function_name))
					for all_inst in caller_inst+callee_inst:
						f.write(all_inst+'\n')

main()





