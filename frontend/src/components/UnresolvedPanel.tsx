import React from 'react';
import type { Event } from '../types/workspace';

interface UnresolvedPanelProps {
  events: Event[];
  unresolvedEventIds: string[];
}

export const UnresolvedPanel: React.FC<UnresolvedPanelProps> = ({ events, unresolvedEventIds }) => {
  const unresolvedEvents = events.filter(e => unresolvedEventIds.includes(e.id));

  if (unresolvedEvents.length === 0) {
    return <div className="ws-empty">All events have been mapped.</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {unresolvedEvents.map(e => (
        <div key={e.id} className="ws-unresolved-item">
          <div className="ws-unresolved-header">
            <span style={{ fontWeight: 700, fontFamily: "'SF Mono', 'Fira Code', monospace", fontSize: '13px', color: 'var(--color-accent)' }}>
              {e.event_type}
            </span>
            <span className="ws-badge" style={{ backgroundColor: 'transparent', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}>
              {e.event_category}
            </span>
          </div>
          <div className="ws-event-details">
            {e.process_name && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">Process:</span>
                <span className="ws-detail-value">{e.process_name}</span>
              </div>
            )}
            {e.source_user && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">User:</span>
                <span className="ws-detail-value">{e.source_user}</span>
              </div>
            )}
            {e.destination_ip && (
              <div className="ws-event-detail">
                <span className="ws-detail-label">Dest:</span>
                <span className="ws-detail-value">{e.destination_ip}:{e.destination_port}</span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};
