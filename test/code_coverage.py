import angr
import IPython
import claripy
import functools
from angrutils import *

def progress_callback(percentage):
    print(type(percentage), percentage)

project = angr.Project("./handsomware.exe",load_options={'auto_load_libs':False})
cfg = project.analyses.CFG()