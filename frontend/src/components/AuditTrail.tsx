import React from 'react';
import type { AnalystAction } from '../types/workspace';

interface AuditTrailProps {
  actions: AnalystAction[];
}

export const AuditTrail: React.FC<AuditTrailProps> = ({ actions }) => {
  if (actions.length === 0) {
    return <div className="ws-empty">No analyst actions recorded yet.</div>;
  }

  return (
    <div className="ws-card">
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {actions.map(action => (
          <div key={action.id} className="ws-audit-row">
            <div className="ws-audit-meta">
              <span className="ws-audit-action">{action.action_type}</span>
              <span>{new Date(action.acted_at).toLocaleString()}</span>
            </div>
            <div style={{ color: 'var(--color-text-primary)' }}>
              Target: {action.target_object_type} ({action.target_object_id.split('-')[0]}...)
            </div>
            {action.reason && (
              <div style={{ fontStyle: 'italic', color: 'var(--color-text-secondary)', marginTop: '4px' }}>
                "{action.reason}"
              </div>
            )}
            <div className="ws-audit-subdued" style={{ marginTop: '4px' }}>
              Analyst: {action.analyst_id}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
