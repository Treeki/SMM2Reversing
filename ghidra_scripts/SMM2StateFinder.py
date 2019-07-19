#TODO write a description for this script
#@author 
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.program.model.pcode.PcodeOp as PcodeOp
import json

DEBUG = False
STOREDEBUG = False

dynamic_ignores = set([
	# these all cannot be determined statically through
	# this script as they don't follow the pattern of one constant
	# state list
	0x71005D3B00, 0x71005D4F90, 0x7100700740, 0x71005D2540, 0x7100AB7070,
	0x71005CFB40,
	0x71005D1790,
	0x7100E37010,
	0x7100BA31D0,
	0x7100BB66A0,
	0x71005ECF50,
	0x710084AAC0,
	0x7100A08230,
	0x7100752920,
	0x71008272F0,
	0x7100739B20,
	0x71006A6720,
	0x71005F87C0,
	0x71006E7AD0,
	0x71006E9A20,

	0x7100AB7070, # doesn't decompile
	0x7100B4ECE0, # decompilation errors
])



empties = []
kludge_names = {
	# 0x7100D05040: 'LessonMenu::MainSeq',
	# 0x7100EC9970: 'ResidentSeq',
	# 0x7100C14620: 'CourseIn::MainSeq',
	# 0x7100E71650: 'UIQuestClearSupportWindowSeq',
	# 0x7100E4DEC0: 'UIScoreSeq',
	# 0x7100E52850: 'UITimeUpSeq',
	# 0x7100E6F8C0: 'UIQuestClearSupportActSeq',
	# 0x7100BD4500: 'UIInfoRealTimeSeq',
	# 0x7100B8C740: 'MessageWindow_00Seq', # used for Qst_MessageWindow_00Seq and Cmn_MessageWindow_00Seq
	# 0x7100E34690: 'UIMissionAttentionSeq',
	# 0x7100BB1520: 'UICommentSceneSeq',
	# 0x7100CC8480: 'UIGameOverSeq',
	# 0x7100EECB70: 'WorldMap::MainSeq',
	# 0x7100EA9160: 'UISlidePassSeq',
	# 0x7100E1EB20: 'UILclBtlResultSeq',
	# 0x7100F016F0: 'MultipleThings', # used for lots of UI elements it seems
	# 0x7100D315E0: 'NetworkFindSeq', # used for NetworkFindMakerSeq, NetworkFindCourseSeq
}
output = []

decompiler = ghidra.app.decompiler.DecompInterface()
decompiler.toggleSyntaxTree(True)
decompiler.toggleCCode(False)
decompiler.openProgram(currentProgram)

allocator_addr = toAddr('allocator')
stateHolderCtor_addr = toAddr('StateHolder_ctor')
stateListCtor_addr = toAddr('StateList_ctor')
stateListPrepare_addr = toAddr('StateList_prepare')
stateSetName_addr = toAddr('StateList_setName')

cstr_vt_addr = toAddr('CStr_vt')
cstr_vt_offset = cstr_vt_addr.getOffset()

register_space = getAddressFactory().getRegisterSpace()
reg08_addr = register_space.getAddress(8)
# reg08_vn = hfunc.findInputVarnode(8, reg08_addr)


def addr(offset):
	# doesn't matter what addr we use, just has to be in the same address space
	if hasattr(offset, 'getOffset'):
		return allocator_addr.getNewAddress(offset.getOffset())
	else:
		return allocator_addr.getNewAddress(offset)

def readStr(addr):
	bits = []
	while True:
		c = getByte(addr)
		if c == 0:
			return ''.join(bits)
		else:
			# TODO getByte returns signed values, fix this
			bits.append(chr(c))
			addr = addr.add(1)

def resolvePcodeToConstant(op):
	if op.getOpcode() in (PcodeOp.CAST, PcodeOp.COPY):
		return resolveVarnode(op.getInput(0))
	elif op.getOpcode() == PcodeOp.PTRSUB:
		return resolveVarnode(op.getInput(1))
	else:
		return None
		# raise ValueError('unknown opcode @ %r' % op)

def resolveVarnode(varnode):
	if varnode.isAddress() or varnode.isConstant():
		return varnode.getAddress()
	# elif varnode.isRegister():
	# 	# TODO make this do something more interesting...?
	# 	return None
	else:
		d = varnode.getDef()
		if d is None:
			print('!!! WARNING !!!')
			print(varnode)
			return None
		return resolvePcodeToConstant(d)

def resolveStackAddr(varnode):
	# known patterns for these:
	#  direct ref to modified sp: reg:08 -> PTRSUB(reg:08 -> null, const:-0x80)
	#  offset from original sp:   unique -> PTRSUB(reg:08 -> null, const:-0x70)
	d = varnode.getDef()
	if d.getOpcode() == PcodeOp.CAST:
		return resolveStackAddr(d.getInput(0))
	elif d.getOpcode() == PcodeOp.PTRSUB:
		assert(d.getInput(0).getAddress() == reg08_addr)
		assert(d.getInput(0).getDef() is None)
		assert(d.getInput(1).isConstant())
		return d.getInput(1).getAddress().getOffset()
	else:
		print(varnode)
		print(d)
		return None
		# raise 'unknown op'

def resolveStruct(varnode):
	d = varnode.getDef()
	if d.getOpcode() == PcodeOp.CAST:
		return resolveStruct(d.getInput(0))
	elif d.getOpcode() == PcodeOp.CALL:
		# this is where the struct was allocated, so just spit it out
		return varnode
	else:
		print(varnode)
		print(d)
		raise 'unknown op'

def extract_multi_left(pvar):
	if isinstance(pvar, tuple) and pvar[0] == 'multi':
		return pvar[1]
	else:
		return pvar

def pvar_add(pvar, num):
	if isinstance(pvar, long):
		return pvar + num
	elif isinstance(pvar, tuple) and pvar[0] == 'add' and isinstance(pvar[2], long):
		return ('add', pvar[1], pvar[2] + num)
	elif isinstance(pvar, tuple) and pvar[0] == 'multi' and isinstance(pvar[1], long):
		# not strictly correct but it makes some cases work
		# and we kinda don't pay attention to MULTIEQUAL at all anyway
		# (we always just use the first value)
		return pvar[1] + num
	else:
		return ('add', pvar, num)

def resolveStructOffset(varnode, depth=0):
	depth += 1
	if depth > 200:
		# print(varnode)
		# raise 'recursing very deeply'
		return ('big recursion', varnode)

	d = varnode.getDef()
	if d is None:
		if varnode.isInput() and varnode.isRegister():
			return varnode
		elif varnode.isConstant():
			return varnode.getAddress().getOffset()
		elif varnode.isInput() and varnode.isAddress() and varnode.getSize() == 8:
			# print('WARNING::: Assuming READ')
			var_ptr = varnode.getAddress()
			var_value = getDataAt(var_ptr).getValue()
			if var_value is None:
				return varnode
			else:
				return var_value.getOffset()
		else:
			print('!!! !!! !!! Null def !!! !!! !!!')
			print(varnode)
			raise 'null def'
	elif d.getOpcode() in (PcodeOp.CAST, PcodeOp.INDIRECT, PcodeOp.COPY):
		return resolveStructOffset(d.getInput(0), depth)
	elif d.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
		# this is where the struct was allocated, so just spit it out
		return varnode
	elif d.getOpcode() == PcodeOp.LOAD:
		return ('load', resolveStructOffset(d.getInput(1), depth))
	elif d.getOpcode() in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
		struc = resolveStructOffset(d.getInput(0), depth)
		if d.getInput(1).isConstant():
			addend = d.getInput(1).getAddress().getOffset()
			return pvar_add(struc, addend)
		else:
			return ('add', struc, d.getInput(1))
	elif d.getOpcode() == PcodeOp.PTRADD:
		struc = resolveStructOffset(d.getInput(0), depth)
		assert(d.getInput(2).isConstant())
		if d.getInput(1).isConstant():
			addend = d.getInput(1).getAddress().getOffset() * d.getInput(2).getAddress().getOffset()
			return pvar_add(struc, addend)
		else:
			return ('ptrAddMult', struc, d.getInput(1), d.getInput(2).getAddress().getOffset())
	elif d.getOpcode() == PcodeOp.INT_AND:
		return ('and', resolveStructOffset(d.getInput(0)), resolveStructOffset(d.getInput(1)))
	elif d.getOpcode() == PcodeOp.INT_RIGHT:
		return ('>>', resolveStructOffset(d.getInput(0)), resolveStructOffset(d.getInput(1)))
	elif d.getOpcode() == PcodeOp.MULTIEQUAL:
		# if depth > 10:
		# 	# kludge to stop FUN_71008ed500 from hitting a horrible case
		# 	return ('MI OVER LIMIT',)
		# return ('multi', resolveStructOffset(d.getInput(0), depth), resolveStructOffset(d.getInput(1), depth))
		return ('multi', resolveStructOffset(d.getInput(0), depth), None)
	else:
		print(varnode)
		print(d)
		raise 'unknown op'

def work_on_function(func):
	print('Working on %r...' % func)
	results = decompiler.decompileFunction(func, 15, monitor)
	hfunc = results.getHighFunction()

	stack_writes = {}
	statelists = []
	statebuffers = []

	holdernames = {}
	bufferToListIndex = {}
	statecounts = {}
	statenames = {}
	statevars = {}

	n = 0
	for block in hfunc.getBasicBlocks():
		# print(block)
		for op in block.getIterator():
			# print('<%d> %r' % (n, op))
			try:
				# resolve stack writes
				# for now we just pretend MULTIEQUAL (phi nodes) doesn't exist
				if op.getOpcode() in (PcodeOp.COPY, PcodeOp.INDIRECT):
					# print('COPY: %r' % op)
					output_addr = op.getOutput().getAddress()
					if output_addr.isStackAddress():
						# print('Stack write %r' % output_addr)
						resolved_src = resolveVarnode(op.getInput(0))
						if resolved_src != None:
							resolved_src_offset = resolved_src.getOffset()
							# if resolved_src_offset == cstr_vt_offset:
							# 	print('Writing CStr!')
							offs = output_addr.getOffset()
							if (offs & 7) == 4 and (offs - 4) in stack_writes:
								# print('ORing extra portion onto var')
								stack_writes[offs - 4] |= (resolved_src.getOffset() << 32)
							else:
								stack_writes[offs] = resolved_src.getOffset()
							# print('...%r' % resolved_src)

				elif op.getOpcode() == PcodeOp.STORE:
					# we want to catch writes into the state structs
					target_vn = op.getInput(1)
					target = resolveStructOffset(target_vn)
					
					if STOREDEBUG:
						print('Store: %r' % (target,))

					# does this match one of the patterns we expect to see for a state write?
					#  ('load', statebuffer)
					#  ('add', ('load', statebuffer), Y)
					#  ('multi', ('add', ('load', statebuffer), X), ('load', statebuffer))
					#  ('add', ('multi', ('add', ('load', statebuffer), X), ('load', statebuffer)), Y)
					is_state_write = False
					if isinstance(target, tuple):
						if target[0] == 'load' and target[1] in statebuffers:
							is_state_write = True
							statebuffer = target[1]
							state_offset = 0
						elif target[0] == 'multi':
							# Store: ('multi', ('add', ('load', ('add', (unique, 0x1000199f, 8), 160L)), 64L), ('load', ('add', (unique, 0x1000199f, 8), 160L)))
							_, left, right = target
							if isinstance(left, tuple) and left[0] == 'add' and isinstance(left[1], tuple):
								if left[1][0] == 'load' and left[1][1] in statebuffers:
									is_state_write = True
									statebuffer = left[1][1]
									state_offset = left[2]
						elif target[0] == 'add' and isinstance(target[1], tuple):
							if target[1][0] == 'load' and target[1][1] in statebuffers:
								is_state_write = True
								statebuffer = target[1][1]
								state_offset = target[2]
							elif isinstance(target[1], tuple) and target[1][0] == 'multi':
								_, left, right = target[1]
								if isinstance(left, tuple) and left[0] == 'add' and isinstance(left[1], tuple):
									if left[1][0] == 'load' and left[1][1] in statebuffers:
										is_state_write = True
										statebuffer = left[1][1]
										state_offset = left[2] + target[2]
						# elif isinstance(target[0], tuple) and target[0][0] == 'load' and target[0][1] in statebuffers:
						# 	is_state_write = True
						# 	statebuffer = target[0][1]
						# 	state_offset = target[1]
						# elif target[0] == 'multi':
						# 	_, left, right = target
						# 	if isinstance(left, tuple) and isinstance(left[0], tuple) and left[0][0] == 'load' and left[0][1] in statebuffers:
						# 		is_state_write = True
						# 		statebuffer = left[0][1]
						# 		state_offset = left[1]
						# elif isinstance(target[0], tuple) and target[0][0] == 'multi':
						# 	_, left, right = target[0]
						# 	if isinstance(left, tuple) and isinstance(left[0], tuple) and left[0][0] == 'load' and left[0][1] in statebuffers:
						# 		is_state_write = True
						# 		statebuffer = left[0][1]
						# 		state_offset = left[1] + target[1]

					# print('<%d> store: target=%r data=%r' % (n, target, data))
					if is_state_write:
						data_vn = op.getInput(2)
						data = resolveStructOffset(data_vn)
						stateList = bufferToListIndex[statebuffer]
						if STOREDEBUG:
							print('<%d> statewrite: list=%r offs=%d data=%r' % (n, stateList, state_offset, data))
						statevars[stateList, state_offset] = data

				elif op.getOpcode() == PcodeOp.CALL:
					call_addr = op.getInput(0).getAddress()
					if call_addr == allocator_addr:
						if DEBUG:
							print('Allocating %r into %r' % (op.getInput(1), op.getOutput()))
					elif call_addr == stateHolderCtor_addr:
						stateHolder = resolveStructOffset(op.getInput(1))
						name_vn = op.getInput(2)
						if name_vn.isInput():
							# exception for e.g. FUN_7100d05040
							if DEBUG:
								print('<StateHolder with unknown/parameter name %r>' % (stateHolder,))
							if func.getEntryPoint().getOffset() in kludge_names:
								holdernames[stateHolder] = kludge_names[func.getEntryPoint().getOffset()]
							else:
								# holdernames[stateHolder] = '???'
								empties.append((func, stateHolder))
						else:
							nameCStr = resolveStackAddr(op.getInput(2))
							if nameCStr != None:
								str_addr = addr(stack_writes[nameCStr + 8])
								name = readStr(str_addr)
								if DEBUG:
									print('StateHolder %r created with CStr %r' % (stateHolder, name))
								holdernames[stateHolder] = name
					elif call_addr == stateListCtor_addr:
						stateList = resolveStructOffset(op.getInput(1))
						if DEBUG:
							print('creating statelist @ %r' % (stateList, ))
						assert(stateList[0] == 'add')
						buf = ('add', stateList[1], stateList[2] + 0x30)
						statelists.append(stateList)
						statebuffers.append(buf)
						bufferToListIndex[buf] = stateList
					elif call_addr == stateListPrepare_addr:
						stateList = resolveStructOffset(op.getInput(1))
						stateCount = resolveVarnode(op.getInput(2)).getOffset()
						if DEBUG:
							print('statelist @ %r has %d states' % (stateList, stateCount))
						statecounts[stateList] = int(stateCount)
					elif call_addr == stateSetName_addr:
						stateList = resolveStructOffset(op.getInput(1))
						stateId = resolveVarnode(op.getInput(2)).getOffset()
						nameCStr = resolveStackAddr(op.getInput(3))
						str_addr = addr(stack_writes[nameCStr + 8])
						name = readStr(str_addr)
						if DEBUG:
							print('statelist @ %r sets name %r to %r' % (stateList, stateId, name))
						statenames[(stateList, int(stateId))] = name
			
			except Exception as e:
				print('FAILED OP:')
				print(op)
				raise
			n += 1
	print('done: %d' % n)

	# go through all of these
	if DEBUG:
		print('HOLDERNAMES: %r' % holdernames)
		print('STATEBUFFERS: %r' % statebuffers)
		print('STATELISTS: %r' % statelists)
		print('STATECOUNTS: %r' % statecounts)
	if STOREDEBUG:
		print('STATEVARS: %r' % statevars)
	for listnum, lst in enumerate(statelists):
		name = 'Func%X::Unnamed%02d' % (func.getEntryPoint().getOffset(), listnum)
		try:
			if isinstance(lst, tuple) and lst[0] == 'add':
				name = 'Func%X::%s@%X' % (func.getEntryPoint().getOffset(), holdernames[lst[1]], lst[2])
		except KeyError:
			name += '_StateHolder@%X' % lst[2]
		if lst in statecounts:
			# find the first vtable
			for i in xrange(statecounts[lst]):
				if (lst,i) in statenames:
					first_vtable = statevars[lst, i*64]
					break

			if STOREDEBUG:
				print(first_vtable)
			output.append('')
			output.append('**%s** (vtable: 0x%X)' % (name, first_vtable))
			output.append('')

			output.append('| ID | Name | Func1 | Func2 | Func3 |')
			output.append('|----|------|-------|-------|-------|')

			for i in xrange(statecounts[lst]):
				def nice_ptmf(o):
					offset = extract_multi_left(statevars[lst, i*64+o])
					flag = extract_multi_left(statevars[lst, i*64+o+8])
					if offset == 0 and flag == 0:
						return 'none'
					elif flag == 0:
						return '0x%X' % (offset,)
					else:
						return 'vf%X' % (offset,)

				if (lst,i) in statenames:
					statename = statenames[lst,i]
					vtable = statevars[lst, i*64]
					assert(vtable == first_vtable)
					ptmf1 = nice_ptmf(0x10)
					ptmf2 = nice_ptmf(0x20)
					ptmf3 = nice_ptmf(0x30)

					output.append('| %d | %s | %s | %s | %s |' % (i, statename, ptmf1, ptmf2, ptmf3))
				else:
					output.append('| %d | *Missing?* | - | - | - |' % i)
		else:
			output.append('')
			output.append('%s: empty' % name)


functions = set()
for ref in getReferencesTo(stateListPrepare_addr):
	func = getFunctionContaining(ref.fromAddress)
	if func is None:
		print('NO FUNCTION: %r' % ref.fromAddress)
	else:
		functions.add(func)


failed = []

# work_on_function(getFunction('FUN_7100538bf0'))
# work_on_function(getFunction('FUN_71005d3b00'))
# 7101080AB0, 71008BF570, 7100EC68F0, 710090CBD0
# work_on_function(getFunction('ActorBuild0_TenCoin'))
# work_on_function(getFunction('FUN_7100ec68f0'))
# work_on_function(getFunction('FUN_710090cbd0'))

n = 0
for func in sorted(functions):
	print('%d/%d...' % (n, len(functions)))
	if func.getEntryPoint().getOffset() in dynamic_ignores:
		print('ignoring because dynamic')
	else:
		try:
			work_on_function(func)
		except Exception as e:
			print(e)
			failed.append(func)
	n += 1
	# if n >= 20:
	# 	break

with open('/Users/ash/src/switch/stateoutput.md', 'w') as f:
	for out in output:
		f.write(out)
		f.write('\n')
		# print(out)

for e in empties:
	print(e)
for f in failed:
	print(f)
