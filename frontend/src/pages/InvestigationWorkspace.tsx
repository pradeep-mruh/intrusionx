import React, { useEffect, useState } from 'react';
import type { WorkspaceData } from '../types/workspace';
import {
  fetchWorkspace,
  confirmRelationship,
  rejectRelationship
} from '../api/client';
import { EvidencePanel } from '../components/EvidencePanel';
import { UnresolvedPanel } from '../components/UnresolvedPanel';
import { ValidationPanel } from '../components/ValidationPanel';
import { AuditTrail } from '../components/AuditTrail';
import { AttackChain } from '../components/AttackChain';
import { EventTimeline } from '../components/EventTimeline';
import './Workspace.css';

export const InvestigationWorkspace: React.FC<{ investigationId: string }> = ({ investigationId }) => {
  const [data, setData] = useState<WorkspaceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const wsData = await fetchWorkspace(investigationId);
      setData(wsData);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to load workspace');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (investigationId) {
      loadData();
    }
  }, [investigationId]);

  const handleConfirm = async (relId: string) => {
    try {
      await confirmRelationship(investigationId, relId);
      await loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleReject = async (relId: string) => {
    try {
      await rejectRelationship(investigationId, relId);
      await loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  if (loading && !data) return <div className="ws-layout" style={{ padding: '48px' }}>Loading Workspace...</div>;
  if (error) return <div className="ws-layout" style={{ padding: '48px', color: 'var(--color-danger)' }}>Error: {error}</div>;
  if (!data) return null;

  return (
    <div className="ws-layout">
      {/* Sidebar */}
      <aside className="ws-sidebar">
        <div className="ws-brand">
          <div className="ws-brand-title">
            <span className="ws-brand-icon">⬡</span>
            <span>IntrusionX</span>
          </div>
          <div className="ws-brand-subtitle">Investigation Workspace</div>
        </div>
        <nav className="ws-nav">
          <a href="#overview" className="ws-nav-link">Overview</a>
          <a href="#evidence" className="ws-nav-link">Evidence</a>
          <a href="#events" className="ws-nav-link">Events</a>
          <a href="#reconstruction" className="ws-nav-link">Reconstruction</a>
          <a href="#validation" className="ws-nav-link">Validation</a>
          <a href="#audit" className="ws-nav-link">Audit Trail</a>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="ws-main">
        <header className="ws-header" id="overview">
          <div>
            <h1 className="ws-title">{data.investigation.title}</h1>
            <div className="ws-meta">
              <span className="ws-badge open">{data.investigation.status}</span>
              <span>ID: {data.investigation.id.substring(0, 8)}...</span>
            </div>
          </div>
          <div className="ws-actions">
            <button onClick={loadData} className="ws-btn">Refresh</button>
          </div>
        </header>

        {/* Metric Cards */}
        <div className="ws-metrics">
          <div className="ws-metric-card">
            <div className="ws-metric-val">{data.evidence.length}</div>
            <div className="ws-metric-label">Evidence Source{data.evidence.length !== 1 ? 's' : ''}</div>
          </div>
          <div className="ws-metric-card">
            <div className="ws-metric-val">{data.events.length}</div>
            <div className="ws-metric-label">Observed Events</div>
          </div>
          <div className="ws-metric-card">
            <div className="ws-metric-val">{data.relationships.length}</div>
            <div className="ws-metric-label">Relationships</div>
          </div>
          <div className="ws-metric-card">
            <div className="ws-metric-val">{data.reconstruction ? 1 : 0}</div>
            <div className="ws-metric-label">Reconstruction</div>
          </div>
          <div className="ws-metric-card">
            <div className="ws-metric-val">{data.unresolved_event_ids?.length || 0}</div>
            <div className="ws-metric-label">Unresolved</div>
          </div>
        </div>

        {/* Reconstruction */}
        <section id="reconstruction" className="ws-section">
          <div>
            <h2 className="ws-section-header">Reconstructed Activity</h2>
            <div className="ws-section-desc">Evidence-Supported Deterministic Relationship Path</div>
          </div>
          <AttackChain
            reconstruction={data.reconstruction}
            events={data.events}
            relationships={data.relationships}
          />
        </section>

        {/* Events Timeline */}
        <section id="events" className="ws-section">
          <div>
            <h2 className="ws-section-header">Observed Events</h2>
            <div className="ws-section-desc">Chronological timeline of all observed telemetry</div>
          </div>
          <EventTimeline events={data.events} />
        </section>

        {/* Unresolved Events */}
        <section className="ws-section">
          <div>
            <h2 className="ws-section-header">Unresolved Events</h2>
            <div className="ws-section-desc">Observed event — no deterministic relationship established.</div>
            <div style={{ fontSize: '13px', color: 'var(--color-text-secondary)', marginBottom: '16px' }}>
              IntrusionX preserves observed telemetry without forcing unsupported causal relationships.
            </div>
          </div>
          <UnresolvedPanel events={data.events} unresolvedEventIds={data.unresolved_event_ids} />
        </section>

        {/* Validation */}
        <section id="validation" className="ws-section">
          <div>
            <h2 className="ws-section-header">Analyst Validation</h2>
            <div className="ws-section-desc">Validate system-proposed relationships</div>
          </div>
          <ValidationPanel
            relationships={data.relationships}
            events={data.events}
            onConfirm={handleConfirm}
            onReject={handleReject}
          />
        </section>

        {/* Evidence & Audit Trail */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '48px' }}>
          <section id="evidence" className="ws-section">
            <div>
              <h2 className="ws-section-header">Evidence</h2>
            </div>
            <EvidencePanel evidence={data.evidence} />
          </section>

          <section id="audit" className="ws-section">
            <div>
              <h2 className="ws-section-header">Audit Trail</h2>
            </div>
            <AuditTrail actions={data.analyst_actions} />
          </section>
        </div>
      </main>
    </div>
  );
};
