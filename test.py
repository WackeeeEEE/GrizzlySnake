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


k32 = windll.kernel32
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

# FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
# FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
# FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

# Fun starts here

class ModuleInformation:
    def __init__(self, index, name, path, address):
        self.index = index
        self.name = name
        self.path = path
        self.address = address

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
    proc = k32.OpenProcess( (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) , 0, pid)
    print(f"PROC", proc)
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

    # Print the process identifier
    print(f"Process ID: {proc}")

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

def printModules(pid):

    print(f"Modules of process {pid}:")

    mods = getModules(pid)

    for mod in mods:
        print(f"Index: {mod.index}\nModule: {mod.name}\nVirtual Address: {mod.address}")

def readP(proc, address, size, *datatype): # size bytes
    data = None
    buffer = create_string_buffer(size)
    counter = c_uint()
    a = readProcMem(proc, address, buffer, size, 0) #[HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
    if a == 0:
        print(GetLastError())
    else:
        print(f"bytes read: {counter.value} | data: {buffer.raw}")#debug
        print("read memory complete") # debug

        raw = buffer.raw
        # print(raw)
        data = raw
        return data

def readP_celevel():

    dlllistOS = 0x038D3BE0 # address of dll list relative to process address
# h1OS = 0x8
# h1levelnameOS = 0x2A6D14C
    proc = getProc(getPIDs(nameProcess)[0])
    counter = c_uint()
    ret = readP(proc, dlllistOS, 16)

def dbg():
    nameProcess = "MCC-Win64-Shipping.exe"
    PIDs = getPIDs(nameProcess)
    if type(PIDs) == type(None):
        print(f"Process {nameProcess} not found")
    else:
        print(f"{len(PIDs)} Processes found, acting on first...")
        proc = getProc(PIDs[0])
        print(f"process object:", type(proc), proc)
        mods = getModules(proc)
    #readP_celevel()

dbg()