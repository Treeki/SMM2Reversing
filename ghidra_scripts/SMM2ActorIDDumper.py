#TODO write a description for this script
#@author 
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.program.model.pcode.PcodeOp as PcodeOp
import json

with open('/Users/ash/src/switch/actorInfo.json', 'r') as f:
	actorInfo = json.load(f)

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
		return varnode
	else:
		return resolvePcodeToConstant(varnode.getDef())


ints = {}

decompiler = ghidra.app.decompiler.DecompInterface()
decompiler.toggleSyntaxTree(True)
decompiler.toggleCCode(False)
decompiler.openProgram(currentProgram)

func = getFunction('sinit_ActorIDs')
results = decompiler.decompileFunction(func, 5, monitor)
hfunc = results.getHighFunction()

for op in hfunc.getPcodeOps():
	if op.getOpcode() in (PcodeOp.COPY, PcodeOp.INDIRECT) and op.getOutput().isAddress():
		#print(op)
		outAddr = op.getOutput().getAddress()
		inVarnode = resolveVarnode(op.getInput(0))
		if inVarnode is None:
			continue

		outOffset = outAddr.getOffset()
		if outOffset == inVarnode.getOffset():
			print('???? %r %r %r ????' % (outAddr, inVarnode, op))
			continue # warn?

		if inVarnode.getSize() == 8:
			high = (inVarnode.getOffset() >> 32) & 0xFFFFFFFF
			low = inVarnode.getOffset() & 0xFFFFFFFF
			ints[outOffset] = int(low)
			ints[outOffset + 4] = int(high)
		else:
			ints[outOffset] = int(inVarnode.getOffset() & 0xFFFFFFFF)


def dumpIntArray(name):
	results = []

	data = getDataAt(toAddr(name))
	addrRange = (data.getMinAddress(), data.getMaxAddress())
	addr = data.getMinAddress()
	while addr < data.getMaxAddress():
		results.append(ints[addr.getOffset()])
		addr = addr.add(4)

	return results

nonEdit = dumpIntArray('NonEditActorIDs')
edit = dumpIntArray('EditActorIDs')
game = dumpIntArray('GameActorIDs')

def niceActorName(n):
	if n == 0xFFFFFFFF:
		return '*none*'
	elif actorInfo[n]['str2']:
		return '*%s*' % actorInfo[n]['str2']
	else:
		return actorInfo[n]['str1']

print('| File ID | Edit | ??? | M1 | M3 | MW | WU | 3W |')
print('|---------|------|-----|----|----|----|----|----|')

for i in xrange(len(nonEdit)):
	bits = (edit[i], nonEdit[i], game[i*5], game[i*5+1], game[i*5+2], game[i*5+3], game[i*5+4])
	mungedBits = [niceActorName(x) for x in bits]
	print('| %d | %s |' % (i, ' | '.join(mungedBits)))


'''for i, eid in enumerate(dumpIntArray('GameActorIDs')):
	if eid == 0xFFFFFFFF:
		print('%d -> NULL' % i)
	else:
		if actorInfo[eid]['str2']:
			print('%d -> %d(%s/%s)' % (i, eid, actorInfo[eid]['str1'], actorInfo[eid]['str2']))
		else:
			print('%d -> %d(%s)' % (i, eid, actorInfo[eid]['str1']))'''
