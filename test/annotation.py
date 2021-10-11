import angr
import IPython
import claripy
import functools


class FakeCreateFileA(angr.SimProcedure):
    def run(self):
        print("FakeCreateFileA")
        return 0xdeadbeef
        # return claripy.BVS("hFile", 16, annotations=(claripy.Annotation(),))


# class FakeReadFile(angr.SimProcedure):
#     def run(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
#         print("FakeReadFile")
#         buffer = claripy.BVS('buffer', 0x1000)
#         self.state.memory.store(lpBuffer, buffer, endness=project.arch.memory_endness)
#         self.state.globals['lpBuffer'] = buffer
        

#         res = claripy.If(hFile == 0xdeadbeef, claripy.BVV(1, 32), claripy.BVV(0, 32))
#         print(res)
#         solution1 = self.state.solver.eval(hFile, cast_to=bytes)
#         print(solution1)
#         return 1

# class FakeWriteFile(angr.SimProcedure):
#     def run(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
#         print("FakeWriteFile")
#         buffer = self.state.memory.load(lpBuffer, 0x1000)
#         print(buffer)
#         return 1


project = angr.Project("./handsomware.exe")
initial_state = project.factory.blank_state(addr=0x401530)
simulation = project.factory.simgr(initial_state)
simulation.use_technique(angr.exploration_techniques.DFS())

project.hook_symbol('CreateFileA', FakeCreateFileA())
# project.hook_symbol('ReadFile', FakeReadFile())
# project.hook_symbol('WriteFile', FakeWriteFile())



handle1 = claripy.BVS('handle1', 16)
handle2 = claripy.BVS('handle2', 16)


def HookSimProcedure(when, state):
    print("SimProcedure when %s name %s" % (when, state.inspect.simprocedure_name))
    # if state.inspect.simprocedure_name is None:
    #     print(state.inspect.__dict__)
    # if state.inspect.simprocedure_name in ["ReadFile", "WriteFile", "GetFileSize", "SetFilePointer"]:
    #     args1 = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
    #     # print(args1)
    #     solution1 = state.solver.eval(args1, cast_to=bytes)
    #     print(solution1)
    #     input("@")
    args1 = state.regs.esp + 4
    if args1.to_claripy().annotations != None:
        print(args1)
        input("@")

def HookCall(when, state):
    args1 = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
    solution1 = state.solver.eval(args1, cast_to=bytes)
    if solution1 == b"\xde\xad\xbe\xef":  
        print(solution1)
        input("@")

initial_state.inspect.b('simprocedure', when=angr.BP_BEFORE, action=functools.partial(HookSimProcedure, "before"))
# initial_state.inspect.b('call', when=angr.BP_BEFORE, action=functools.partial(HookCall, "before"))



paths = []
while True:
    succ = simulation.step()

    active_addrs = [ sim.addr for sim in simulation.active]


    ### setup buffer1 of handle value
    if 0x401576 in active_addrs:
        input("After CreateFileA")
        
    if 0x40159A in active_addrs:
        input("First Branch")

    if 0x401807 in active_addrs:
        input("After ReadFile")

    if 0x401934 in active_addrs:
        input("After WriteFile")
        

