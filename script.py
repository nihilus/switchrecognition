from idaapi import *
from random import randint

def FindBlock(ea):
    f = FlowChart(get_func(get_func(ea).startEA))
    for block in f:
        if block and ea >= block.startEA and ea < block.endEA:
            return block
    return None

def colorBlock (addr, color):
    bb = FindBlock(addr)
    for ea in Heads(bb.startEA, bb.endEA):
        SetColor(ea, CIC_ITEM, color)

def FindSeg(segName):
    segEA = FirstSeg()
    while SegName(segEA) != segName:
        segEA = NextSeg(segEA)
        #print SegName(segEA) + " trouve a l'adresse " + hex(segEA)
    return segEA

textEA = FindSeg(".text")
rodataEA = FindSeg(".rodata")
print ""
print ""
print ""
print ""
print "Searching for jumptables ..."

JTaddresses = [] #the potential addresses of jump tables, and the address of their reference
#we browse every function of .text
for funcea in Functions(SegStart(textEA), SegEnd(textEA)):
    startFunc = GetFunctionAttr(funcea,FUNCATTR_START)
    endFunc = GetFunctionAttr(funcea,FUNCATTR_END)
    nameFunc = GetFunctionName(startFunc)
    #we browse every instruction of the current function
    ea = startFunc
    while ea <= endFunc:
        #we are looking for an instruction pattern
        #if we find a match, we memorize the JumpTable and the instruction addresses
        if GetMnem(ea) == "mov":
            if GetOpType(ea, 1) == 2:
                if "*4]" in GetOpnd(ea, 1):
                    jumpTableEA = GetOperandValue(ea,1)
                    JTaddresses = JTaddresses + [(jumpTableEA,ea)]
        if GetMnem(ea) == "jmp":
            if GetOpType(ea, 0) == 2:
                if "*4]" in GetOpnd(ea, 0):
                    jumpTableEA = GetOperandValue(ea,0)
                    JTaddresses = JTaddresses + [(jumpTableEA,ea)]
            if GetOpType(ea, 0) == 1:
                prevInst = PrevHead(ea)
                if GetOpType(prevInst, 1) == 5:
                    jumpTableEA = GetOperandValue(prevInst,1)
                    if (SegStart(rodataEA)<=jumpTableEA and jumpTableEA<=SegEnd(rodataEA)):
                        JTaddresses = JTaddresses + [(jumpTableEA,prevInst)]
                prevInst = PrevHead(prevInst)
                if GetOpType(prevInst, 1) == 5:
                    jumpTableEA = GetOperandValue(prevInst,1)
                    if (SegStart(rodataEA)<=jumpTableEA and jumpTableEA<=SegEnd(rodataEA)):
                        JTaddresses = JTaddresses + [(jumpTableEA,prevInst)]

        ea=NextHead(ea)

#we sort the addresses of the jumpTables by their addresses
JTaddresses.sort()

#we browse every potential jump table found
#JTcontent contains the content of the current jumpTable
JTcontent = []
JTfound = False
for JT in JTaddresses:
    #we verify if its address is in .rodata
    if (True):#(SegStart(rodataEA)<=JT[0] and JT[0]<=SegEnd(rodataEA)):
        JTfirstEntry = Dword(JT[0])
        JTcontent = [JTfirstEntry]
        #we verify if its first entry points to .text
        if (SegStart(textEA)<=JTfirstEntry and JTfirstEntry<=SegEnd(textEA)):
            currentFunc = GetFunctionName(JTfirstEntry)
            currPtr = JT[0]+4
            currEntry = Dword(currPtr)
            #we browse every entry of the jump table
            while (GetFunctionName(currEntry) == currentFunc):
                #we stop if we arrive on the next jump table
                if (JT != JTaddresses[-1] and currPtr == JTaddresses[JTaddresses.index(JT)+1][0]):
                    break
                #we memorize the addresses contained in the jump table
                JTcontent.append(currEntry)
                currPtr = currPtr + 4
                currEntry = Dword(currPtr)
            if (len(JTcontent)>1):
                JTfound = True
                print "JumpTable found at " + hex(JT[0]) + " (" + str(len(JTcontent)) + " cases)"

                #we comment&color the blocks
                color = randint(1, 1 << 24)
                MakeComm(JT[1], "switch with " + str(len(JTcontent)) + " cases")
                colorBlock(JT[1], color)
                MakeComm(JT[0], "jumptable for switch " + hex(JT[1]))
                for caseEA in JTcontent:
                    colorBlock(caseEA, color)
                    MakeComm(caseEA, "case n" + str(JTcontent.index(caseEA)))
if (not JTfound):
    print "No jumptable was found"