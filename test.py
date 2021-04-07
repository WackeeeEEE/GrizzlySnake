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

unpack_dict = {
    type(c_int64()):"Q",          # 8 bytes
    type(c_int32()):"i",          # 4 bytes
    type(c_float()):"f",          # 4 bytes
    type(c_double()):"d",         # 8 bytes
    type(int()):"Q"
}


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

    def readP(self, address, size, datatype=None): # size bytes
        data = None
        buffer = create_string_buffer(size)
        counter = c_ulonglong()
        a = readProcMem(self.handle, address, buffer, size, byref(counter))
        if a == 0:
            print(f"ERROR: {GetLastError()}\n{FormatError(GetLastError())}")
        else:
            if datatype != None:
                # data = unpack("<"+unpack_dict[type(datatype)], buffer.raw)[0]
                # print(f"data interpreted as {type(datatype)}: {data}")

                if type(datatype) == type(int()):
                    data = unpack("<Q",buffer.raw)[0]
                    #print(f"data interpreted as {type(datatype)}: {data}")
            else:
                raw = buffer.raw
                data = raw
                #print(f"raw output: {data}")
            return data

    #[0x038D3BE0, 0x8, 0x2A6D14C]
    def readDeepP(self, deepPointer, size):
        pt = self.readP(self.address+deepPointer[0], 8, datatype=int())
        for offset in deepPointer[1:-1]:
            pt = self.readP(pt+offset, 8, datatype=int())
        data = self.readP(pt+deepPointer[-1], size)
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
        levelBytes = self.readDeepP([0x038D3BE0, 0x8, 0x2A6D14C], 3)
        print(f"Current level: {levelBytes.decode('utf-8')}")

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
    else:
        print(f"{len(PIDs)} Processes found, acting on first PID - {PIDs[0]}")
        print(PIDs)
        proc = Process(PIDs[0], nameProcess)

        # Test individual levels of deep pointer method, uses int(), must fix
        l1_pointer = proc.readP(proc.address+0x038D3BE0, 8, datatype=int())
        l2_pointer = proc.readP(l1_pointer+0x8, 8, datatype=int())

        # Test getting address relative to halo1.dll via module address
        proc.listModules(key="halo1.dll")


        for mod in proc.mods:
            if mod.name == "halo1.dll":
                resp = proc.readP(mod.address+0x2A6D14C, 3)
                #print(resp)
        
        # Test levelname string via Class method method
        levelBytes = proc.readDeepP([0x038D3BE0, 0x8, 0x2A6D14C], 3)
        print(f"Current level: {levelBytes.decode('utf-8')}")
        #print(len(levelBytes), type(levelBytes))
        #levelName = str(''.join([unpack("<c", i) for i in levelBytes]))
        # for i in levelBytes:
        #     print(i)
        # print(levelName)
    
        return proc
a = start_here()
