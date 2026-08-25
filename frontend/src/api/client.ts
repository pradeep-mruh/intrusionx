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
