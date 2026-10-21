import React from 'react';
import type { AnalystAction } from '../types/workspace';

interface AuditTrailProps {
  actions: AnalystAction[];
}

function actionClass(actionType: string): string {
  const t = actionType.toUpperCase();
  if (t.includes('CONFIRM')) return 'confirm';
  if (t.includes('REJECT')) return 'reject';
  return 'default';
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
              <span className={`ws-audit-action ${actionClass(action.action_type)}`}>
                {action.action_type}
              </span>
              <span className="ws-audit-time">
                {new Date(action.acted_at).toLocaleString([], {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                  hour12: false,
                })}
              </span>
            </div>
            <div className="ws-audit-target">
              {action.target_object_type} — {action.target_object_id.substring(0, 8)}…
            </div>
            {action.reason && (
              <div style={{ fontStyle: 'italic', color: 'var(--color-text-secondary)', fontSize: '11px' }}>
                "{action.reason}"
              </div>
            )}
            <div className="ws-audit-subdued">
              Analyst: {action.analyst_id}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
