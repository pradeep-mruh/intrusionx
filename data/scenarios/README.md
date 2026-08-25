# Attack Scenarios

Named attack scenarios used for end-to-end testing of the full pipeline.

Each scenario should be a subdirectory containing:
- `README.md` — description of the scenario, attacker techniques, and expected reconstruction
- `evidence/` — raw evidence files for this scenario
- `expected/` — expected correlation and reconstruction output (for test assertions)

Example scenario structure:

```
scenarios/
└── lateral_movement_smb/
    ├── README.md
    ├── evidence/
    │   ├── auth.log
    │   └── process_events.json
    └── expected/
        ├── relationships.json
        └── attack_chain.json
```
