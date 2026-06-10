import { getStore } from "@netlify/blobs";
import { parseCookies, SESSION_COOKIE, SESSION_STORE } from "../lib/auth.js";

const PUBLIC_PATHS = new Set(["/login.html", "/login"]);

function isPublicPath(pathname) {
  if (PUBLIC_PATHS.has(pathname)) return true;
  if (pathname.startsWith("/.netlify/")) return true;
  return false;
}

export default async (request, context) => {
  const url = new URL(request.url);

  if (isPublicPath(url.pathname)) {
    return context.next();
  }

  const cookies = parseCookies(request.headers.get("cookie"));
  const sessionId = cookies[SESSION_COOKIE];

  if (!sessionId) {
    return Response.redirect(new URL("/login.html", url.origin), 302);
  }

  const store = getStore(SESSION_STORE);
  const session = await store.get(sessionId, { type: "json" });

  if (!session) {
    return Response.redirect(new URL("/login.html", url.origin), 302);
  }

  return context.next();
};
