import React from 'react';
import type { Relationship, Event } from '../types/workspace';

interface ValidationPanelProps {
  relationships: Relationship[];
  events: Event[];
  onConfirm: (relId: string) => void;
  onReject: (relId: string) => void;
}

function getEventLabel(events: Event[], id: string): string {
  const ev = events.find(e => e.id === id);
  if (!ev) return 'Unknown Event';
  return ev.process_name || ev.file_path?.split('\\').pop()?.split('/').pop() || ev.event_type;
}

export const ValidationPanel: React.FC<ValidationPanelProps> = ({ relationships, events, onConfirm, onReject }) => {
  if (relationships.length === 0) {
    return <div className="ws-empty">No relationships to validate.</div>;
  }

  return (
    <div className="ws-card">
      {relationships.map(rel => {
        let statusClass = 'proposed';
        if (rel.status === 'ANALYST_CONFIRMED') statusClass = 'confirmed';
        if (rel.status === 'ANALYST_REJECTED') statusClass = 'rejected';

        const sourceLabel = getEventLabel(events, rel.source_event_id);
        const targetLabel = getEventLabel(events, rel.target_event_id);

        return (
          <div key={rel.id} className="ws-val-card">
            <div className="ws-val-header">
              <div className="ws-val-title">
                {rel.relationship_type}
                <span className={`ws-val-status ${statusClass}`}>{rel.status}</span>
              </div>
            </div>

            {/* Directional relationship path */}
            <div className="ws-val-path">
              <span className="ws-val-path-node">{sourceLabel}</span>
              <span className="ws-val-path-arrow">→</span>
              <span className="ws-val-path-node">{targetLabel}</span>
            </div>

            {rel.explanation && (
              <div className="ws-val-desc" style={{ fontStyle: 'italic' }}>
                "{rel.explanation}"
              </div>
            )}

            {rel.status === 'SYSTEM_PROPOSED' && (
              <div className="ws-val-actions">
                <button onClick={() => onConfirm(rel.id)} className="ws-btn ws-btn-primary">Confirm</button>
                <button
                  onClick={() => onReject(rel.id)}
                  className="ws-btn"
                  style={{ color: 'var(--color-danger)', borderColor: 'rgba(248, 81, 73, 0.3)' }}
                >
                  Reject
                </button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
