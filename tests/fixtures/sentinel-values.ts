/**
 * Synthetic sentinel values used only in tests and fixtures. These are not
 * real credentials. Tests assert that these exact strings never appear in
 * any generated output (terminal, JSON, or error messages).
 */
export const SENTINEL_JWT_SECRET = 'sentinel-jwt-9f13c2b7e4a1';
export const SENTINEL_DB_PASSWORD = 'sentinel-db-pass-4471aab0';
export const SENTINEL_API_KEY = 'sentinel-api-key-77f0d3';

export const ALL_SENTINEL_VALUES = [
  SENTINEL_JWT_SECRET,
  SENTINEL_DB_PASSWORD,
  SENTINEL_API_KEY,
] as const;
