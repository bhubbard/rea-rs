use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMachineSpec {
    pub initial_state: String,
    pub states: Vec<String>,
    pub transitions: Vec<ReplayTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTransition {
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvent {
    pub name: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayExecutionJournal {
    pub initial_state: String,
    pub final_state: String,
    pub steps_taken: usize,
    pub transitions_recorded: Vec<RecordedTransition>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedTransition {
    pub step: usize,
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub action_executed: Option<String>,
}

pub fn run_replay_machine(
    spec: &ReplayMachineSpec,
    events: &[ReplayEvent],
) -> Result<ReplayExecutionJournal> {
    let mut current_state = spec.initial_state.clone();
    let mut transitions_recorded = Vec::new();

    // Index transitions: (from_state, event) -> (to_state, action)
    let mut transition_map: HashMap<(String, String), (String, Option<String>)> = HashMap::new();
    for t in &spec.transitions {
        transition_map.insert(
            (t.from_state.clone(), t.event.clone()),
            (t.to_state.clone(), t.action.clone()),
        );
    }

    for (step, event) in events.iter().enumerate() {
        let key = (current_state.clone(), event.name.clone());
        if let Some((next_state, action)) = transition_map.get(&key) {
            transitions_recorded.push(RecordedTransition {
                step,
                from_state: current_state.clone(),
                event: event.name.clone(),
                to_state: next_state.clone(),
                action_executed: action.clone(),
            });
            current_state = next_state.clone();
        } else {
            return Ok(ReplayExecutionJournal {
                initial_state: spec.initial_state.clone(),
                final_state: current_state.clone(),
                steps_taken: step,
                transitions_recorded,
                success: false,
                error_message: Some(format!(
                    "No valid transition from state '{}' on event '{}'",
                    current_state, event.name
                )),
            });
        }
    }

    Ok(ReplayExecutionJournal {
        initial_state: spec.initial_state.clone(),
        final_state: current_state,
        steps_taken: events.len(),
        transitions_recorded,
        success: true,
        error_message: None,
    })
}
