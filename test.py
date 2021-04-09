###################### NOTES #######################

# pointerStr = "[0x038D3BE0, 0x8, 0x2A6D14C], 3"
# h1dll_level = 0x2A6D14C
# read from addresses
# STRLEN = 255

# PROCESS_VM_READ = 0x0010

# k32 = WinDLL('kernel32')
# k32.OpenProcess.argtypes = DWORD,BOOL,DWORD
# k32.OpenProcess.restype = HANDLE
# k32.ReadProcessMemory.argtypes = HANDLE,LPVOID,LPVOID,c_size_t,POINTER(c_size_t)
# k32.ReadProcessMemory.restype = BOOL

# process = k32.OpenProcess(PROCESS_VM_READ, 0, PROCESS_ID)
# buf = create_string_buffer(STRLEN)
# s = c_size_t()
# if k32.ReadProcessMemory(process, PROCESS_HEADER_ADDR, buf, STRLEN, byref(s)):
#     print(s.value,buf.raw)


# "MCC-Win64-Shipping.exe"
# "halo1.dll"

# c# (vars.H1_levelname = new StringWatcher(new DeepPointer(0x038D3BE0, 0x8, 0x2A6D14C), 3)),
# ps1 aed30000

# rPM = ctypes.WinDLL('kernel32',use_last_error=True).ReadProcessMemory
# rPM.argtypes = [wintypes.HANDLE,wintypes.LPCVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
# rPM.restype = wintypes.BOOL
# wPM = ctypes.WinDLL('kernel32',use_last_error=True).WriteProcessMemory
# wPM.argtypes = [wintypes.HANDLE,wintypes.LPVOID,wintypes.LPCVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
# wPM.restype = wintypes.BOOL
        
# moduleFilterFlag = 0x03


# def readMem(address, size):
#     bufferNBC = ctypes.create_string_buffer(size)
#     readProcMem(process, address, bufferNBC, size, 0)
#     return bufferNBC.raw
    
# def writeMem(address, data):
#     writeProcMem(process, address, data, len(data), 0)

###################### NOTES END ###################

from ctypes import *
from ctypes.wintypes import *
import psutil

from struct import *

import json
from types import SimpleNamespace

import asyncio
#import threading
import time

k32 = windll.kernel32
openProc = k32.OpenProcess
openProc.argtypes = DWORD, BOOL, DWORD
openProc.restype = HANDLE
readProcMem = k32.ReadProcessMemory
readProcMem.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
readProcMem.restype = BOOL
writeProcMem = k32.WriteProcessMemory
writeProcMem.argtypes = [HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
psapi = windll.psapi
psapi.GetModuleFileNameExA.argtypes = [HANDLE, HMODULE, LPSTR, DWORD]
psapi.GetModuleFileNameExA.restype = BOOL


nameProcess = "MCC-Win64-Shipping.exe"
pointers = json.load(open("pointers.json", "r"), object_hook=lambda d: SimpleNamespace(**d)) # might wanna change this, namespace stuff scary
strToType = {
    "string":str(),
    "int":int(),
    "float":float()
}

PROCESS_VM_READ = 0x0010 # READ-ONLY
PROCESS_ALL_ACCESS = 0x1F0FFF # MORE_ACCESS
PROCESS_QUERY_INFORMATION = 0x0400

# Fun starts here

class ModuleInformation:
    def __init__(self, index, name, path, address):
        self.index = index
        self.name = name
        self.path = path
        self.address = address

class Process:
    def __init__(self, pid, name):
        self.pid = pid
        self.handle = openProc(PROCESS_ALL_ACCESS, False, self.pid)
        self.mods = getModules(self.handle)
        self.name = name
        self.address = None
        for mod in self.mods:
            if mod.name == self.name:
                self.address = mod.address
        if self.address == None:
            print("PROCESS ADDRESS NOT FOUND")
        else:
            print(f"Process {self.name} found at {self.address}")

    def readP(self, address, size):#, datatype=None): # size bytes
        data = None
        buffer = create_string_buffer(size)
        counter = c_ulonglong()
        a = readProcMem(self.handle, address, buffer, size, byref(counter))
        if a == 0:
            print(f"ERROR: {GetLastError()}\n{FormatError(GetLastError())}")
        else:
            # if datatype != None:
            #     # data = unpack("<"+unpack_dict[type(datatype)], buffer.raw)[0]
            #     # print(f"data interpreted as {type(datatype)}: {data}")

            #     if type(datatype) == type(int()):
            #         data = unpack("<Q",buffer.raw)[0]
            #         #print(f"data interpreted as {type(datatype)}: {data}")
            # else:
                # = buffer.raw
                #data = raw
                #print(f"raw output: {data}")
            return Fragment(address, buffer.raw) #data

    def readDeepP(self, deepPointer, size, datatype=None):
        pt = self.readP(self.address+deepPointer[0], 8).asPtr()
        for offset in deepPointer[1:-1]:
            pt = self.readP(pt+offset, 8).asPtr()
        data = self.readP(pt+deepPointer[-1], size)
        if datatype != None: # might implement this on the next highest level, not sure yet - ex: data return will be as"Type"()
            if type(datatype) == type(int()):
                #print(f"as type {type(datatype)}: {data.asInt()}")
                if len(data.raw) == 4:
                    return data.asInt32()
            if type(datatype) == type(str()):
                #print(f"as type {type(datatype)}: {data.asStr()}")
                return data.asStr()
            if type(datatype) == type(float()):
                #print(f"as type {type(datatype)}: {data.asFloat()}")
                return data.asFloat()
            # if type(datatype) == type(ptr()): #eeeeeeeh, do i have to?
            #     print("as type {type(datatype)}: {data.asPtr()}")
        return data

    def listModules(self, key=None):
        for mod in self.mods:
            if key == None:
                print(f"Index: {mod.index} | Name: {mod.name} | Address: {mod.address}")
            else:
                if mod.name == key:
                    print(f"Index: {mod.index} | Name: {mod.name} | Address: {mod.address}")


    ### Testy Stuff ###

    def printLevel(self):
        level = pointers.halo1.level
        #levelPointer = Pointer(level.offsets, level.length, level.type)# shorten
        levelPointer = PointerShort(level)
        levelFragment = self.readDeepP(levelPointer.offsets, levelPointer.length, levelPointer.type)
        # print(f"Current level: {levelFragment.asStr()}")

class Fragment:
    def __init__(self, address, raw):
        self.address = address
        self.raw = raw
        self.size = len(self.raw)
        
    def __doc__():
        return "Arbitrarily sized block of process data"
    def asInt(self):
        return unpack("<Q", self.raw)[0]
    def asInt32(self):
        return unpack("<i", self.raw)[0]
    def asStr(self):
        return self.raw.decode('utf-8')
    def asFloat(self):
        return unpack("<d", self.raw)[0]
    def asPtr(self): #kinda just for clarity, dont think i really need
        return unpack("<Q", self.raw)[0]

class Pointer:
    def __init__(self, offsets, length, type): # list/tuple in

        self.offsets = [] # converting string hex/int? to int
        for offset in offsets:
            self.offsets.append(int(offset, 0)) # using 0 base to invoke guessing base, useful for different types in db?

        self.length = length
        self.type = strToType[type]

class PointerShort:
    def __init__(self, pointerObj): # composite arg in

        self.offsets = [] # converting string hex/int? to int
        for offset in pointerObj.offsets:
            self.offsets.append(int(offset, 0)) # using 0 base to invoke guessing base, useful for different types in db?

        self.length = pointerObj.length
        self.type = strToType[pointerObj.type]

class Governor:
    def __init__(self):
        self.objects = []

    def ready(self, obj):
        if time.time() >= obj.lastRun+obj.interval:
            obj.run()

    def addWatcher(self, obj):
        self.objects.append(obj)

    def listWatchers(self):
        watcherStr = str('\n'.join([obj.name for obj in self.objects]))
        print(f"Current Watchers:{watcherStr}")

    def loop(self):
        while True:
            #time.sleep(5)
            for obj in self.objects:
                self.ready(obj)


class Watcher:
    def __init__(self, proc, pointer, name, interval=1):
        self.proc = proc
        self.pointer = pointer

        self.name = name
        self.interval = interval
        self.lastRun = 0



        # thread = threading.Thread(target=self.run, args=())
        # #thread.daemon = True
        # thread.start()

    def run(self):
        print(self.proc.readDeepP(self.pointer.offsets, self.pointer.length, datatype=self.pointer.type))
        self.lastRun = time.time()

class Phone:
    def __init__(self, string):
        self.string = string
    
    def __repr__(self) -> str:
        return self.string

def getPIDs(nameProcess):
    found = []
    for proc in psutil.process_iter():
        if str(nameProcess) in str(proc.name):
            print("FOUND", nameProcess)
            found.append(proc.pid)
    try:
        if len(found) > 0:
            return found
    except Exception as e:
        print(type(e), e)
        return None

def getProc(pid):

    # Get a handle to the process
    proc = openProc( (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) , False, pid)
    if proc == 0:
        print(f"ERROR: {GetLastError()}\n{FormatError(GetLastError())}")
    else:
        return proc

def getModules(proc):

    # Get a handle to the process
    hProcess = proc

    # Set up vars
    arr = HMODULE * 1024
    hMods = arr() 
    cbNeeded = c_ulong()
    modNameArray = c_char * MAX_PATH
    clearName = modNameArray()
    szModName = modNameArray()

    # Get a list of all the modules in this process
    EnumAttempt = psapi.EnumProcessModules(hProcess, hMods, sizeof(hMods), byref(cbNeeded))
    if EnumAttempt == 0:
        print(GetLastError())
    else:
        mods = []

        for i, val in enumerate(hMods[:int(cbNeeded.value / sizeof(HMODULE))]):
            memmove(byref(szModName), byref(clearName), sizeof(clearName))
            if val != None:
                modAttempt = psapi.GetModuleFileNameExA(hProcess, val, szModName, int(sizeof(szModName) / sizeof(c_char)))
                if modAttempt == 0:
                    print(GetLastError())
                else:
                    index = i
                    name = str(b''.join([i for i in szModName if i != b'\x00'])).split("\\")[-1][:-1]
                    path = str(b''.join([i for i in szModName if i != b'\x00']))[2:-1]
                    address = val
                    mods.append(ModuleInformation(index, name, path, address))
            else:
                pass
        return mods

def printModules(pid, proc):

    print(f"Modules of process {pid}:")
    proc = getProc(pid)
    mods = getModules(proc)

    for mod in mods:
        print(f"Index: {mod.index}\nModule: {mod.name}\nVirtual Address: {mod.address}")

def start_here():
    nameProcess = "MCC-Win64-Shipping.exe"
    PIDs = getPIDs(nameProcess)
    if type(PIDs) == type(None):
        print(f"Process {nameProcess} not found")
        proc = None
    else:
        print(f"{len(PIDs)} Processes found, acting on first PID - {PIDs[0]}")
        print(PIDs)
        proc = Process(PIDs[0], nameProcess)
    return proc

    
MCC = start_here()
g = Governor()
level = pointers.halo1.level
levelWatcher = Watcher(MCC, PointerShort(level), name="h1-level", interval=5)

tick = pointers.halo1.tick
tickWatcher = Watcher(MCC, PointerShort(tick), name="tick", interval=.5)
g.addWatcher(levelWatcher)
g.addWatcher(tickWatcher)
g.loop()