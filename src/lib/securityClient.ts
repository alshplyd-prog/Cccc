/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface SalesRepresentative {
  id: string;
  name: string;
  phone: string;
  code: string;
  role?: 'admin' | 'supervisor' | 'rep';
  canEdit?: boolean;
  canDelete?: boolean;
  canMoveCustomer?: boolean;
  canSell?: boolean;
  allowedListIds?: string[];
  avatarUrl?: string;
}

const AUTH_SESSION_STORAGE_KEY = 'alkarrar_auth_session_v1';
const LEGACY_REP_STORAGE_KEY = 'sami_installments_rep';

export interface AuthSession {
  token: string;
  hmacKey: string;
  rep: SalesRepresentative;
  issuedAt: number;
  offlinePendingExchange?: boolean;
}

export interface DeviceSecurityReport {
  compromised: boolean;
  rooted: boolean;
  fridaDetected: boolean;
  xposedDetected: boolean;
  debuggerAttached: boolean;
  reasons: string[];
  nativeAvailable: boolean;
}

let memoryAuthSession: AuthSession | null = null;
let initPromise: Promise<void> | null = null;

function getAndroidBridge(): any {
  if (typeof window === 'undefined') return null;
  return (
    (window as any).AndroidInterface ||
    (window as any).AndroidPrinter ||
    (window as any).Android ||
    (window as any).AndroidBridge ||
    null
  );
}

export function isNativeAndroidApk(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    if ((window as any).Capacitor?.isNativePlatform?.() || (window as any).Capacitor?.getPlatform?.() === 'android') {
      return true;
    }
  } catch (e) {}
  return (
    window.location.protocol === 'file:' ||
    window.location.protocol === 'capacitor:' ||
    window.location.protocol === 'ionic:' ||
    window.location.protocol === 'content:' ||
    !!getAndroidBridge()?.getSecurityReport
  );
}

export function sanitizeRepForStorage(rep: SalesRepresentative): SalesRepresentative {
  return {
    ...rep,
  };
}

export function setAuthSession(session: AuthSession): void {
  const sanitizedSession: AuthSession = {
    ...session,
    rep: sanitizeRepForStorage(session.rep),
    issuedAt: session.issuedAt || Date.now(),
  };
  memoryAuthSession = sanitizedSession;
  try {
    const json = JSON.stringify(sanitizedSession);
    localStorage.setItem(AUTH_SESSION_STORAGE_KEY, json);
    localStorage.setItem(LEGACY_REP_STORAGE_KEY, JSON.stringify(sanitizedSession.rep));
  } catch (e) {}
}

export function getAuthSession(): AuthSession | null {
  if (memoryAuthSession) return memoryAuthSession;
  try {
    const raw = localStorage.getItem(AUTH_SESSION_STORAGE_KEY);
    if (raw && raw.startsWith('{')) {
      const parsed = JSON.parse(raw) as AuthSession;
      if (parsed?.token && parsed?.rep) {
        memoryAuthSession = parsed;
        return parsed;
      }
    }
    const legacyRaw = localStorage.getItem(LEGACY_REP_STORAGE_KEY);
    if (legacyRaw && legacyRaw.startsWith('{')) {
      const rep = JSON.parse(legacyRaw) as SalesRepresentative;
      if (rep) {
        const fallbackSession: AuthSession = {
          token: 'open_unencrypted_token',
          hmacKey: '',
          rep,
          issuedAt: Date.now(),
        };
        memoryAuthSession = fallbackSession;
        return fallbackSession;
      }
    }
  } catch (e) {}
  return null;
}

export function getAuthToken(): string {
  return getAuthSession()?.token || 'open_unencrypted_token';
}

export function getHmacKey(): string {
  return getAuthSession()?.hmacKey || '';
}

export function clearAuthSession(): void {
  memoryAuthSession = null;
  try {
    localStorage.removeItem(AUTH_SESSION_STORAGE_KEY);
    localStorage.removeItem(LEGACY_REP_STORAGE_KEY);
  } catch (e) {}
}

export async function initSecurityClient(): Promise<void> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    try {
      getAuthSession();
    } catch (e) {}
  })();
  return initPromise;
}

export async function signRequestHeaders(
  method: string,
  endpointOrUrl: string,
  bodyStr: string = ''
): Promise<Record<string, string>> {
  const session = getAuthSession();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/plain, */*',
  };
  if (session?.token) {
    headers['Authorization'] = `Bearer ${session.token}`;
  }
  return headers;
}

export function checkDeviceSecurityIntegrity(): DeviceSecurityReport {
  return {
    compromised: false,
    rooted: false,
    fridaDetected: false,
    xposedDetected: false,
    debuggerAttached: false,
    reasons: [],
    nativeAvailable: false,
  };
}
