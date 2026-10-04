import React from 'react';
import type { Reconstruction, Event, Relationship } from '../types/workspace';

interface AttackChainProps {
  reconstruction: Reconstruction | null;
  events: Event[];
  relationships: Relationship[];
}

export const AttackChain: React.FC<AttackChainProps> = ({ reconstruction, events, relationships }) => {
  if (!reconstruction) {
    return <div className="ws-empty">No reconstruction snapshot available.</div>;
  }

  // Check if any relationships in the snapshot have been rejected by the analyst
  const hasRejectedRelationships = reconstruction.steps.some(step => {
    if (step.step_type === 'RELATIONSHIP' && step.relationship_id) {
      const rel = relationships.find(r => r.id === step.relationship_id);
      return rel && rel.status === 'ANALYST_REJECTED';
    }
    return false;
  });

  return (
    <div>
      {hasRejectedRelationships && (
        <div className="ws-warning">
          <strong>Warning:</strong> Reconstruction snapshot contains a relationship subsequently rejected by an analyst.
        </div>
      )}

      <div className="ws-recon-flow">
        {reconstruction.steps.map((step, idx) => {
          if (step.step_type === 'EVENT' && step.event_id) {
            const ev = events.find(e => e.id === step.event_id);
            let displayLabel = 'Unknown';
            let subtitle = '';

            if (ev?.event_type === 'FILE_CREATE' || ev?.event_type === 'FILE_DELETE') {
              const fullPath = ev.file_path || '';
              // Extract basename (handles both Windows and Unix paths)
              displayLabel = fullPath.split('\\').pop()?.split('/').pop() || 'Unknown File';
              subtitle = 'FILE';
            } else if (ev?.event_type === 'PROCESS_START' || ev?.process_name) {
              displayLabel = ev.process_name || 'Unknown Process';
              subtitle = ev.process_id ? `PID: ${ev.process_id}` : 'PROCESS';
            } else {
              displayLabel = ev?.event_type || 'Unknown';
            }

            return (
              <div key={idx} className="ws-recon-node">
                <div>{displayLabel}</div>
                {subtitle && <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginTop: '4px' }}>{subtitle}</div>}
              </div>
            );
          } else if (step.step_type === 'RELATIONSHIP' && step.relationship_id) {
            const rel = relationships.find(r => r.id === step.relationship_id);

            let statusClass = 'proposed';
            if (rel?.status === 'ANALYST_CONFIRMED') statusClass = 'confirmed';
            if (rel?.status === 'ANALYST_REJECTED') statusClass = 'rejected';

            return (
              <div key={idx} className="ws-recon-edge">
                <div className="ws-recon-line"></div>
                <div className={`ws-recon-label ${statusClass}`}>
                  {rel?.relationship_type || 'UNKNOWN'}
                </div>
                <div className="ws-recon-line"></div>
                <div className="ws-recon-arrow"></div>
              </div>
            );
          }
          return null;
        })}
      </div>
    </div>
  );
};
