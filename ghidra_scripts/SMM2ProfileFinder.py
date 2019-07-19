#TODO write a description for this script
#@author 
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.program.model.pcode.PcodeOp as PcodeOp
import json

actorTable = getDataAt(toAddr('maybeBaseOfActorTable'))
acRange = (actorTable.getMinAddress(), actorTable.getMaxAddress())

profVtable = toAddr('Profile_vtable').getOffset()
print(repr(profVtable))
profileIDsByAddr = {}
profileObjectsSeen = set()
profileIDsSeen = set()
writes = {}

decompiler = ghidra.app.decompiler.DecompInterface()
decompiler.toggleSyntaxTree(True)
decompiler.toggleCCode(False)
decompiler.openProgram(currentProgram)

def addr(offset):
	return acRange[0].getNewAddress(offset)

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
		#raise ValueError('unknown opcode @ %r' % op)

def resolveVarnode(varnode):
	if varnode.isAddress() or varnode.isConstant():
		return varnode.getAddress()
	else:
		return resolvePcodeToConstant(varnode.getDef())


def workOnThing(func):
	print('Working on %r...' % func)
	results = decompiler.decompileFunction(func, 5, monitor)
	hfunc = results.getHighFunction()

	for op in hfunc.getPcodeOps():
		if op.getOpcode() in (PcodeOp.COPY, PcodeOp.INDIRECT) and op.getOutput().isAddress():
			#print(op)
			outAddr = op.getOutput().getAddress()
			inValue = resolveVarnode(op.getInput(0))
			if inValue is None:
				continue

			outOffset = outAddr.getOffset()
			if outOffset == inValue.getOffset():
				continue # warn?

			writes[outOffset] = inValue.getOffset()
			if inValue.getOffset() == profVtable:
				profileObjectsSeen.add(outAddr)

			#print('write %r to %r' % (inValue, outAddr))

			if outAddr >= acRange[0] and outAddr <= acRange[1]:
				actorID = outAddr.subtract(acRange[0]) // 8
				profileIDsSeen.add(actorID)
				print('Found write %r to actortable for num %d' % (inValue, actorID))
				print(repr(op.getInput(0)))


'''workOnThing(toAddr('sinit_BulletBone'))
workOnThing(toAddr('sinit_BulletEnemyFire'))'''
#workOnThing(toAddr('fkx2'))

functionsToCheck = set()
acheck = acRange[0]
while acheck < acRange[1]:
	for ref in getReferencesTo(acheck):
		if ref.getReferenceType().isWrite():
			functionsToCheck.add(getFunctionContaining(ref.getFromAddress()))
	acheck = acheck.add(8)

print(len(functionsToCheck))
i = 0
for fn in functionsToCheck:
	print ('%d...' % i),
	workOnThing(fn)
	i += 1

'''init_array = getMemoryBlock('.init_array')
i = 0
iapos = init_array.getStart()
while iapos < init_array.getEnd() and i < 200:
	print ('%d... ' % i),
	fn_addr = getDataAt(iapos).getValue()
	if getInstructionAt(fn_addr) is None:
		print('gonna disassemble %r' % fn_addr)
		disassemble(fn_addr)
	if getFunctionAt(fn_addr) is None:
		print('gonna create fn %r' % fn_addr)
		createFunction(fn_addr, None)
	workOnThing(getFunctionAt(fn_addr))
	iapos = iapos.add(8)
	i += 1'''

print(profileIDsSeen)
#print(i)

profType = getDataTypes('ActorProfile')[0]

results = []

for i in sorted(profileIDsSeen):
	offset = writes[acRange[0].add(i * 8).getOffset()]
	print('%d -> %x' % (i, offset))

	assert(writes[offset] == profVtable)

	address = addr(offset)
	if getDataAt(address).dataType != profType:
		clearListing(address, address.add(profType.getLength() - 1))
		createData(address, profType)

	buildAddr = addr(writes[offset + 8])
	if getInstructionAt(buildAddr) is None:
		disassemble(buildAddr)
	if getFunctionAt(buildAddr) is None:
		createFunction(buildAddr, None)

	_10 = (writes[offset + 0x10] & 0xFFFFFFFF)
	_14 = ((writes[offset + 0x10] >> 32) & 0xFFFFFFFF)
	_18 = writes[offset + 0x18]
	_20 = writes[offset + 0x20]
	_24 = writes[offset + 0x24]
	str1 = readStr(addr(writes[offset + 0x30]))
	str2 = readStr(addr(writes[offset + 0x40]))
	print('%d -> %r,%r' % (i, str1, str2))

	createLabel(address, 'ActorProfile%d_%s' % (i, str1), True)
	createLabel(buildAddr, 'ActorBuild%d_%s' % (i, str1), True)

	assert(len(results) == i)
	results.append({
		'profile': offset,
		'buildFunc': buildAddr.getOffset(),
		'_10': _10,
		'_14': _14,
		'_18': _18,
		'_20': _20,
		'_24': _24,
		'str1': str1,
		'str2': str2
	})

with open('/Users/ash/src/switch/actorInfo.json', 'w') as f:
	json.dump(results, f)
