/**
 * Base URL for all backend API requests.
 *
 * In local development: the Vite dev server proxies /health (and later
 * /api/*) to http://localhost:8000, so an empty base URL works.
 *
 * In Docker Compose or production: VITE_API_BASE_URL should be set to the
 * backend origin (e.g. http://localhost:8000).
 */
const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? ''

export interface HealthResponse {
  status: string
  database: string
  version: string
}

/**
 * Fetch the backend health status.
 * Returns null if the backend is unreachable or returns a non-2xx status.
 */
export async function fetchHealth(): Promise<HealthResponse | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`)
    if (!response.ok) {
      return null
    }
    return (await response.json()) as HealthResponse
} catch {
    return null
  }
}

import type { WorkspaceData } from '../types/workspace';

const INVESTIGATIONS_API_BASE = `${API_BASE_URL}/api/v1/investigations`;

export const DEMO_ANALYST_ID = '00000000-0000-0000-0000-000000000001';

export async function fetchWorkspace(investigationId: string): Promise<WorkspaceData> {
  const res = await fetch(`${INVESTIGATIONS_API_BASE}/${investigationId}/workspace`);
  if (!res.ok) throw new Error('Failed to fetch workspace');
  return res.json();
}

export async function correlateInvestigation(investigationId: string) {
  const res = await fetch(`${INVESTIGATIONS_API_BASE}/${investigationId}/correlate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to correlate');
  return res.json();
}

export async function reconstructInvestigation(investigationId: string) {
  const res = await fetch(`${INVESTIGATIONS_API_BASE}/${investigationId}/reconstruct`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to reconstruct');
  return res.json();
}

export async function confirmRelationship(
  investigationId: string,
  relationshipId: string,
  reason: string = 'Analyst confirmed via workspace'
) {
  const res = await fetch(`${INVESTIGATIONS_API_BASE}/${investigationId}/relationships/${relationshipId}/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: DEMO_ANALYST_ID, reason }),
  });
  if (!res.ok) throw new Error('Failed to confirm relationship');
  return res.json();
}

export async function rejectRelationship(
  investigationId: string,
  relationshipId: string,
  reason: string = 'Analyst rejected via workspace'
) {
  const res = await fetch(`${INVESTIGATIONS_API_BASE}/${investigationId}/relationships/${relationshipId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: DEMO_ANALYST_ID, reason }),
  });
  if (!res.ok) throw new Error('Failed to reject relationship');
  return res.json();
}
