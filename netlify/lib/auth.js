export const SESSION_COOKIE = "goad_session";
export const SESSION_STORE = "sessions";
export const SESSION_MAX_AGE = 60 * 60 * 24 * 7;

export function normalizeSecret(value) {
  return String(value ?? "").replace(/\s+/g, "").toLowerCase();
}

export function isValidPassword(input, expected) {
  const target = expected || process.env.SITE_PASSWORD || "ThereIsNoSpoon";
  return normalizeSecret(input) === normalizeSecret(target);
}

export function parseCookies(header) {
  if (!header) return {};
  return header.split(";").reduce((acc, part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return acc;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) acc[key] = value;
    return acc;
  }, {});
}

export function sessionCookie(sessionId) {
  return `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
