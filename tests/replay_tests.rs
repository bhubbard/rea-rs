use rea::replay::machine::{
    run_replay_machine, ReplayEvent, ReplayMachineSpec, ReplayTransition,
};
use serde_json::json;

#[test]
fn test_finite_replay_machine_success() {
    let spec = ReplayMachineSpec {
        initial_state: "IDLE".to_string(),
        states: vec!["IDLE".to_string(), "RUNNING".to_string(), "STOPPED".to_string()],
        transitions: vec![
            ReplayTransition {
                from_state: "IDLE".to_string(),
                event: "START".to_string(),
                to_state: "RUNNING".to_string(),
                action: Some("allocate_buffers".to_string()),
            },
            ReplayTransition {
                from_state: "RUNNING".to_string(),
                event: "STOP".to_string(),
                to_state: "STOPPED".to_string(),
                action: Some("release_resources".to_string()),
            },
        ],
    };

    let events = vec![
        ReplayEvent {
            name: "START".to_string(),
            payload: json!({}),
        },
        ReplayEvent {
            name: "STOP".to_string(),
            payload: json!({}),
        },
    ];

    let journal = run_replay_machine(&spec, &events).expect("replay execution");
    assert!(journal.success);
    assert_eq!(journal.final_state, "STOPPED");
    assert_eq!(journal.steps_taken, 2);
    assert_eq!(journal.transitions_recorded.len(), 2);
    assert_eq!(
        journal.transitions_recorded[0].action_executed.as_deref(),
        Some("allocate_buffers")
    );
}

#[test]
fn test_finite_replay_machine_invalid_transition() {
    let spec = ReplayMachineSpec {
        initial_state: "IDLE".to_string(),
        states: vec!["IDLE".to_string(), "RUNNING".to_string()],
        transitions: vec![ReplayTransition {
            from_state: "IDLE".to_string(),
            event: "START".to_string(),
            to_state: "RUNNING".to_string(),
            action: None,
        }],
    };

    let events = vec![ReplayEvent {
        name: "UNKNOWN_EVENT".to_string(),
        payload: json!({}),
    }];

    let journal = run_replay_machine(&spec, &events).expect("replay execution");
    assert!(!journal.success);
    assert!(journal.error_message.is_some());
    assert_eq!(journal.final_state, "IDLE");
}
