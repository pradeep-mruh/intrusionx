import { useState, useEffect } from 'react'
import { fetchHealth } from './api/client'
import type { HealthResponse } from './api/client'
import { InvestigationWorkspace } from './pages/InvestigationWorkspace'
import './App.css'

type HealthStatus = 'loading' | 'healthy' | 'degraded' | 'unreachable'

function statusColor(status: HealthStatus): string {
  switch (status) {
    case 'healthy':
      return 'var(--color-success)'
    case 'degraded':
      return 'var(--color-warning)'
    case 'unreachable':
      return 'var(--color-danger)'
    default:
      return 'var(--color-text-secondary)'
  }
}

function statusLabel(status: HealthStatus): string {
  switch (status) {
    case 'loading':
      return 'Checking…'
    case 'healthy':
      return 'Healthy'
    case 'degraded':
      return 'Degraded'
    case 'unreachable':
      return 'Unreachable'
  }
}

export default function App() {
  const [healthStatus, setHealthStatus] = useState<HealthStatus>('loading')
  const [healthData, setHealthData] = useState<HealthResponse | null>(null)

  const searchParams = new URLSearchParams(window.location.search);
  const investigationId = searchParams.get('investigation');

  useEffect(() => {
    async function checkHealth() {
      const data = await fetchHealth()
      if (data === null) {
        setHealthStatus('unreachable')
        return
      }
      setHealthData(data)
      if (data.status === 'ok' && data.database === 'connected') {
        setHealthStatus('healthy')
      } else {
        setHealthStatus('degraded')
      }
    }

    checkHealth()
  }, [])

  if (investigationId) {
    return <InvestigationWorkspace investigationId={investigationId} />;
  }

  return (
    <div className="app-layout">
      <header className="app-header">
        <div className="header-brand">
          <span className="brand-icon">⬡</span>
          <span className="brand-name">IntrusionX</span>
        </div>
        <nav className="header-nav">
          <span className="nav-item nav-item--active">Overview</span>
        </nav>
      </header>

      <main className="app-main">
        <section className="hero">
          <h1 className="hero-title">Evidence-Driven Attack Reconstruction</h1>
          <p className="hero-subtitle">
            Ingest security telemetry → normalize events → discover relationships →
            reconstruct attack chains → validate with human investigators.
          </p>
        </section>

        <section className="system-status">
          <h2 className="section-title">System Status</h2>
          <div className="status-grid">
            <div className="status-card">
              <div className="status-card__label">Frontend</div>
              <div className="status-card__value" style={{ color: 'var(--color-success)' }}>
                Running
              </div>
              <div className="status-card__detail">React + Vite</div>
            </div>

            <div className="status-card">
              <div className="status-card__label">Backend API</div>
              <div
                className="status-card__value"
                style={{ color: statusColor(healthStatus) }}
              >
                {statusLabel(healthStatus)}
              </div>
              <div className="status-card__detail">
                {healthData ? `v${healthData.version}` : 'FastAPI'}
              </div>
            </div>

            <div className="status-card">
              <div className="status-card__label">Database</div>
              <div
                className="status-card__value"
                style={{
                  color:
                    healthData?.database === 'connected'
                      ? 'var(--color-success)'
                      : healthStatus === 'loading'
                        ? 'var(--color-text-secondary)'
                        : 'var(--color-danger)',
                }}
              >
                {healthStatus === 'loading'
                  ? 'Checking…'
                  : healthData?.database === 'connected'
                    ? 'Connected'
                    : 'Disconnected'}
              </div>
              <div className="status-card__detail">PostgreSQL 16</div>
            </div>
          </div>
        </section>

        <section className="pipeline-overview">
          <h2 className="section-title">Pipeline</h2>
          <div className="pipeline">
            {[
              { stage: 'Ingestion', description: 'Receive raw security evidence' },
              { stage: 'Normalization', description: 'Convert to common event schema' },
              { stage: 'Correlation', description: 'Discover event relationships' },
              { stage: 'Reconstruction', description: 'Build candidate attack chains' },
              { stage: 'Investigation', description: 'Human validation and confirmation' },
            ].map((item, index, arr) => (
              <div key={item.stage} className="pipeline-row">
                <div className="pipeline-stage">
                  <div className="pipeline-stage__name">{item.stage}</div>
                  <div className="pipeline-stage__description">{item.description}</div>
                </div>
                {index < arr.length - 1 && (
                  <div className="pipeline-arrow" aria-hidden="true">→</div>
                )}
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="app-footer">
        <span>IntrusionX — initial setup</span>
        <span>
          <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer">
            API Docs
          </a>
        </span>
      </footer>
    </div>
  )
}
