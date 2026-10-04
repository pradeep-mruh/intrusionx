import React from 'react';
import type { Relationship, Event } from '../types/workspace';

interface ValidationPanelProps {
  relationships: Relationship[];
  events: Event[];
  onConfirm: (relId: string) => void;
  onReject: (relId: string) => void;
}

export const ValidationPanel: React.FC<ValidationPanelProps> = ({ relationships, events, onConfirm, onReject }) => {
  if (relationships.length === 0) {
    return <div className="ws-empty">No relationships to validate.</div>;
  }

  const getEventStr = (id: string) => {
    const ev = events.find(e => e.id === id);
    if (!ev) return 'Unknown Event';
    return `${ev.event_type} (${ev.process_name || ev.file_path || 'unknown'})`;
  };

  return (
    <div className="ws-card">
      {relationships.map(rel => {
        let statusClass = 'proposed';
        if (rel.status === 'ANALYST_CONFIRMED') statusClass = 'confirmed';
        if (rel.status === 'ANALYST_REJECTED') statusClass = 'rejected';

        return (
          <div key={rel.id} className="ws-val-card">
            <div className="ws-val-header">
              <div className="ws-val-title">
                {rel.relationship_type}
                <span className={`ws-val-status ${statusClass}`}>{rel.status}</span>
              </div>
            </div>
            <div className="ws-val-desc">
              <span className="ws-detail-label">Source:</span> {getEventStr(rel.source_event_id)} <br/>
              <span className="ws-detail-label">Target:</span> {getEventStr(rel.target_event_id)}
            </div>
            {rel.explanation && <div className="ws-val-desc" style={{ fontStyle: 'italic', marginTop: '4px' }}>"{rel.explanation}"</div>}

            {rel.status === 'SYSTEM_PROPOSED' && (
              <div className="ws-val-actions">
                <button onClick={() => onConfirm(rel.id)} className="ws-btn ws-btn-primary">Confirm</button>
                <button onClick={() => onReject(rel.id)} className="ws-btn" style={{ color: 'var(--color-danger)', borderColor: 'rgba(248, 81, 73, 0.3)' }}>Reject</button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
