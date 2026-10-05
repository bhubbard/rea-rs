use crate::types::{BasicBlock, CfgEdge, CfgEdgeType, ControlFlowGraph, DisassembledInstruction, FlowType};
use std::collections::{BTreeSet, HashMap};

pub fn build_cfg(
    procedure_name: impl Into<String>,
    instructions: &[DisassembledInstruction],
) -> ControlFlowGraph {
    let procedure_name = procedure_name.into();
    if instructions.is_empty() {
        return ControlFlowGraph {
            procedure_name,
            entry_address: 0,
            blocks: Vec::new(),
            edges: Vec::new(),
        };
    }

    let entry_address = instructions[0].address;

    // 1. Identify leaders
    let mut leaders = BTreeSet::new();
    leaders.insert(instructions[0].address);

    let address_to_idx: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, inst)| (inst.address, i))
        .collect();

    for (i, inst) in instructions.iter().enumerate() {
        match inst.flow_type {
            FlowType::ConditionalBranch | FlowType::UnconditionalBranch => {
                if let Some(target) = inst.target_address {
                    if address_to_idx.contains_key(&target) {
                        leaders.insert(target);
                    }
                }
                // Instruction following branch is a leader
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].address);
                }
            }
            FlowType::Return => {
                if i + 1 < instructions.len() {
                    leaders.insert(instructions[i + 1].address);
                }
            }
            _ => {}
        }
    }

    // 2. Partition into BasicBlocks
    let sorted_leaders: Vec<u64> = leaders.into_iter().collect();
    let mut blocks = Vec::new();
    let mut addr_to_block_id = HashMap::new();

    for (block_id, &leader_addr) in sorted_leaders.iter().enumerate() {
        addr_to_block_id.insert(leader_addr, block_id);
    }

    for (block_id, &leader_addr) in sorted_leaders.iter().enumerate() {
        let start_idx = *address_to_idx.get(&leader_addr).unwrap();
        let end_idx = if block_id + 1 < sorted_leaders.len() {
            let next_leader = sorted_leaders[block_id + 1];
            *address_to_idx.get(&next_leader).unwrap()
        } else {
            instructions.len()
        };

        let block_instructions = instructions[start_idx..end_idx].to_vec();
        let start_address = block_instructions[0].address;
        let end_address = block_instructions.last().map(|i| i.address).unwrap_or(start_address);

        blocks.push(BasicBlock {
            id: block_id,
            start_address,
            end_address,
            instruction_count: block_instructions.len(),
            instructions: block_instructions,
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
    }

    // 3. Connect CFG edges
    let mut edges = Vec::new();

    for i in 0..blocks.len() {
        let last_inst = match blocks[i].instructions.last() {
            Some(inst) => inst.clone(),
            None => continue,
        };

        match last_inst.flow_type {
            FlowType::ConditionalBranch => {
                // Branch target
                if let Some(target) = last_inst.target_address {
                    if let Some(&target_block_id) = addr_to_block_id.get(&target) {
                        edges.push(CfgEdge {
                            from_block: i,
                            to_block: target_block_id,
                            edge_type: CfgEdgeType::BranchTrue,
                        });
                    }
                }
                // Fallthrough to next block
                if i + 1 < blocks.len() {
                    edges.push(CfgEdge {
                        from_block: i,
                        to_block: i + 1,
                        edge_type: CfgEdgeType::BranchFalse,
                    });
                }
            }
            FlowType::UnconditionalBranch => {
                if let Some(target) = last_inst.target_address {
                    if let Some(&target_block_id) = addr_to_block_id.get(&target) {
                        edges.push(CfgEdge {
                            from_block: i,
                            to_block: target_block_id,
                            edge_type: CfgEdgeType::Unconditional,
                        });
                    }
                }
            }
            FlowType::Return => {
                // No successors
            }
            _ => {
                // Fallthrough to next block if exists
                if i + 1 < blocks.len() {
                    edges.push(CfgEdge {
                        from_block: i,
                        to_block: i + 1,
                        edge_type: CfgEdgeType::Fallthrough,
                    });
                }
            }
        }
    }

    // Populate successors and predecessors in blocks
    for edge in &edges {
        if edge.from_block < blocks.len() && edge.to_block < blocks.len() {
            blocks[edge.from_block].successors.push(edge.to_block);
            blocks[edge.to_block].predecessors.push(edge.from_block);
        }
    }

    ControlFlowGraph {
        procedure_name,
        entry_address,
        blocks,
        edges,
    }
}
