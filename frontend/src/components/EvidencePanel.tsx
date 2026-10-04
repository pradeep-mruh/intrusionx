import React from 'react';
import type { Evidence } from '../types/workspace';

interface EvidencePanelProps {
  evidence: Evidence[];
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({ evidence }) => {
  if (evidence.length === 0) {
    return <div className="ws-empty">No evidence imported.</div>;
  }

  return (
    <div className="ws-card">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {evidence.map(e => (
          <div key={e.id} style={{ paddingBottom: '12px', borderBottom: '1px solid var(--color-border)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{e.source_identifier}</span>
              <span className="ws-badge" style={{ backgroundColor: 'rgba(88, 166, 255, 0.1)', color: 'var(--color-accent)' }}>
                {e.normalized_event_count} Events
              </span>
            </div>
            <div className="ws-detail-label" style={{ marginTop: '4px', fontSize: '12px' }}>
              Imported: {new Date(e.imported_at).toLocaleString()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
