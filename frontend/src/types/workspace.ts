export interface Investigation {
  id: string;
  title: string;
  status: string;
  created_at: string;
}

export interface Evidence {
  id: string;
  source_identifier: string;
  content_hash: string;
  imported_at: string;
  normalized_event_count: number;
}

export interface Event {
  id: string;
  occurred_at: string;
  event_type: string;
  event_category: string;
  source_host?: string;
  source_user?: string;
  process_name?: string;
  process_id?: number;
  parent_process_id?: number;
  file_path?: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  action?: string;
}

export interface Relationship {
  id: string;
  relationship_type: string;
  status: 'SYSTEM_PROPOSED' | 'ANALYST_CONFIRMED' | 'ANALYST_REJECTED';
  creation_method: string;
  explanation?: string;
  source_event_id: string;
  target_event_id: string;
  status_changed_at?: string;
}

export interface ReconstructionStep {
  step_order: number;
  step_type: 'EVENT' | 'RELATIONSHIP' | 'GAP';
  event_id?: string;
  relationship_id?: string;
}

export interface Reconstruction {
  id: string;
  title: string;
  status: string;
  created_at: string;
  steps: ReconstructionStep[];
}

export interface AnalystAction {
  id: string;
  action_type: string;
  target_object_type: string;
  target_object_id: string;
  analyst_id: string;
  previous_state: Record<string, any>;
  new_state: Record<string, any>;
  reason?: string;
  acted_at: string;
}

export interface WorkspaceData {
  investigation: Investigation;
  evidence: Evidence[];
  events: Event[];
  relationships: Relationship[];
  reconstruction: Reconstruction | null;
  unresolved_event_ids: string[];
  analyst_actions: AnalystAction[];
}
