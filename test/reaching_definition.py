import angr 
import autoblob
import os
import angr.analyses.reaching_definitions.dep_graph as dep_graph

from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.knowledge_plugins.key_definitions.definition import Tag
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.key_definitions.tag import ParameterTag

from networkx.drawing.nx_agraph import write_dot

# Utility class to walk back the definitions graph.
class DefinitionExplorer():
    def __init__(self, project, rd_ddg_graph):
        self.project = project
        self.rd_ddg_graph = rd_ddg_graph

    def resolve_use_def(self, reg_def):
        # Now we need to analyze the definition for this atom
        reg_seen_defs = set()
        defs_to_check = set()
        defs_to_check.add(reg_def)
    
        # Cache of all seen nodes (Tie the knot)
        seen_defs = set()

        while len(defs_to_check) != 0:
            current_def = defs_to_check.pop()
            seen_defs.add(current_def) 
            # Check if the current Definition has a tag 
            def_value = self.check_definition_tag(current_def)
            
            # If def_value is not None we hit a "retval" and we collect it,
            # in the other case we need to check if it is Undefined, if yes gotta walk back. 
            if def_value:
                reg_seen_defs.add(def_value)
            else:
                dataset = current_def.data 
                # Boolean guard: do we have any undefined pointers? 
                undefined_pointers = False 
                
                # A value in DataSet can be "Int" or "Undefined"
                for data in dataset:
                    if type(data) == Undefined: undefined_pointers = True  

                # If we have undefined pointers (a.k.a. Top value) we need to process the predecessors.
                if undefined_pointers:
                    for pred in self.rd_ddg_graph.graph.predecessors(current_def):
                        if pred not in seen_defs:
                            defs_to_check.add(pred)
                else:
                     # This is a constant.
                    def_value = ("int", None)
                    reg_seen_defs.add(def_value)

        return reg_seen_defs

    # Checking the tag over a definition.
    def check_definition_tag(self, definition):
        if len(definition.tags) > 0:
            curr_tag = definition.tags.pop() # Ok just take the first one as for now.
            if type(curr_tag) == ReturnValueTag:
                return ("retval",curr_tag.function) 
            else:
                print(type(curr_tag))
                return None

# Path of the blob.
blob_path = "./atmel_6lowpan_udp_rx.bin"

# Address of memcpy function.
memcpy_addr = 0xf647

print("Creating angr Project")
project = angr.Project(blob_path)

print("Creating binary CFG")
bin_cfg = project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True, 
                                force_complete_scan=False, normalize=True, symbols=True)

# Get CFG node for memcpy
memcpy_node = bin_cfg.model.get_any_node(memcpy_addr)
# Get all the XRefs (predecessor of the memcpy nodes)
memcpy_node_preds = memcpy_node.predecessors
# Get the CC of memcpy
memcpy_cc =  project.kb.functions[memcpy_addr].calling_convention

# Grab all functions that have an xrefs to the basic function
memcpy_funcs_preds = list(set([x.function_address for x in memcpy_node_preds]))

# Creating a dictionary of predecessors functions and the address 
# of the xrefs to the memcpy 
FUNC_PREDECESSORS = {}
for memcpy_func_pred_addr in memcpy_funcs_preds:
    FUNC_PREDECESSORS[str(memcpy_func_pred_addr)] = []
for x in memcpy_node_preds:
    FUNC_PREDECESSORS[str(x.function_address)].append(x)

OVERALL_DEFS = set()
FUNCS = set()

for memcpy_func_pred_addr, xrefs in FUNC_PREDECESSORS.items():
    memcpy_func_pred_addr = int(memcpy_func_pred_addr)
    print("Now analyzing predecessor func at {}".format(hex(memcpy_func_pred_addr)))
    print("XRefs are {}".format((xrefs)))
    
    for xref in xrefs:
        print("-->Analyzing XRefs at {}".format(hex(xref.addr)))
        # Get the Function object of the func containing the xref to memcpy
        memcpy_func_pred = bin_cfg.functions.get_by_addr(memcpy_func_pred_addr)

        # Call to the bf function is the last instruction of the block.
        call_to_xref_address = project.factory.block(xref.addr).instruction_addrs[-1]
        
        try:
            rd = project.analyses.ReachingDefinitions(subject=memcpy_func_pred, 
                                                      func_graph=memcpy_func_pred.graph,
                                                      cc = memcpy_func_pred.calling_convention,
                                                      observation_points= [("insn", call_to_xref_address , 0)],
                                                      dep_graph = dep_graph.DepGraph()
                                                     )
        except Exception as e:
            # Sorry for this, sometimes it explodes :)
            continue

        rd_ddg_graph = rd.dep_graph
        # Instantiate the object that will walk back the dep_graph.
        def_explorer = DefinitionExplorer(project, rd_ddg_graph)
        
        # Get the VEX offset for "r0"
        reg_vex_offset = project.arch.registers.get("r0", None)[0]
        
        if rd.observed_results != {}:
            # Cycle all over the results 
            for observed_result in rd.observed_results.items():
                reg_defs = observed_result[1].register_definitions.get_objects_by_offset(reg_vex_offset)
                for reg_def in reg_defs:
                    reg_seen_defs = def_explorer.resolve_use_def(reg_def)
                    for definition in reg_seen_defs:
                        OVERALL_DEFS.add(definition)

            for definition in OVERALL_DEFS:
                if definition[0] == "retval":
                    # It's not always guaranteed that the retval tag of a definition has the
                    # func addr, in those casese we call it a day (definition[1] will be None).
                    if definition[1] != None:
                        FUNCS.add(hex(definition[1]))
print(FUNCS)