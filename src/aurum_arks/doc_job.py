"""Windows limits for processes created by this mission; no system configuration."""
import ctypes as C
from ctypes import wintypes as W
import os

from .serialization import ContractError


class Basic(C.Structure):
    _fields_=[('PerProcessUserTimeLimit',C.c_int64),('PerJobUserTimeLimit',C.c_int64),
              ('LimitFlags',W.DWORD),('MinimumWorkingSetSize',C.c_size_t),('MaximumWorkingSetSize',C.c_size_t),
              ('ActiveProcessLimit',W.DWORD),('Affinity',C.c_size_t),('PriorityClass',W.DWORD),('SchedulingClass',W.DWORD)]


class IO(C.Structure):
    _fields_=[(n,C.c_uint64) for n in ('ReadOperationCount','WriteOperationCount','OtherOperationCount',
                                     'ReadTransferCount','WriteTransferCount','OtherTransferCount')]


class Extended(C.Structure):
    _fields_=[('BasicLimitInformation',Basic),('IoInfo',IO),('ProcessMemoryLimit',C.c_size_t),
              ('JobMemoryLimit',C.c_size_t),('PeakProcessMemoryUsed',C.c_size_t),('PeakJobMemoryUsed',C.c_size_t)]


def kernel():
    if os.name!='nt': raise ContractError('WINDOWS_JOB_REQUIRED')
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateJobObjectW.argtypes=[C.c_void_p,W.LPCWSTR]; k.CreateJobObjectW.restype=W.HANDLE
    k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD]; k.SetInformationJobObject.restype=W.BOOL
    k.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p]; k.QueryInformationJobObject.restype=W.BOOL
    k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]; k.AssignProcessToJobObject.restype=W.BOOL
    k.TerminateJobObject.argtypes=[W.HANDLE,W.UINT]; k.TerminateJobObject.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE]; k.CloseHandle.restype=W.BOOL
    k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD]; k.OpenProcess.restype=W.HANDLE
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]; k.WaitForSingleObject.restype=W.DWORD
    k.GetProcessTimes.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p]; k.GetProcessTimes.restype=W.BOOL
    return k


class OwnedJob:
    def __init__(self,memory_mib=256):
        if type(memory_mib) is not int or not 64<=memory_mib<=1024: raise ContractError('JOB_MEMORY_LIMIT')
        self.k=kernel(); self.handle=self.k.CreateJobObjectW(None,None)
        if not self.handle: raise ContractError('JOB_CREATE_FAILED')
        info=Extended(); info.BasicLimitInformation.LimitFlags=0x2000|0x200
        info.JobMemoryLimit=memory_mib*1024*1024
        if not self.k.SetInformationJobObject(self.handle,9,C.byref(info),C.sizeof(info)):
            self.close(); raise ContractError('JOB_LIMIT_FAILED')
        observed=Extended()
        if not self.k.QueryInformationJobObject(self.handle,9,C.byref(observed),C.sizeof(observed),None):
            self.close(); raise ContractError('JOB_QUERY_FAILED')
        if observed.JobMemoryLimit!=info.JobMemoryLimit or observed.BasicLimitInformation.LimitFlags & 0x2200 !=0x2200:
            self.close(); raise ContractError('JOB_LIMIT_NOT_OBSERVED')
        self.observed={'memory_bytes':observed.JobMemoryLimit,'kill_on_close':True,'scope':'owned process tree'}

    def assign(self,process):
        if not self.k.AssignProcessToJobObject(self.handle,W.HANDLE(int(process._handle))):
            raise ContractError('JOB_ASSIGN_FAILED')

    def terminate(self,code=124):
        if self.handle and not self.k.TerminateJobObject(self.handle,code): raise ContractError('JOB_TERMINATE_FAILED')

    def close(self):
        if self.handle: self.k.CloseHandle(self.handle); self.handle=None


def observe_process(pid):
    """No scan. Observe only a recorded PID; creation time detects PID reuse."""
    k=kernel(); handle=k.OpenProcess(0x1000|0x100000,False,pid)
    if not handle:
        code=C.get_last_error()
        return {'pid':pid,'state':'NOT_FOUND' if code==87 else 'UNKNOWN','winerror':code}
    try:
        times=[C.c_uint64() for _ in range(4)]
        creation=None
        if k.GetProcessTimes(handle,*(C.byref(t) for t in times)): creation=times[0].value
        wait=k.WaitForSingleObject(handle,0)
        return {'pid':pid,'creation_filetime':creation,'state':'RUNNING' if wait==258 else 'EXITED' if wait==0 else 'UNKNOWN'}
    finally: k.CloseHandle(handle)
