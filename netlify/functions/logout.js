import { getStore } from "@netlify/blobs";
import { clearSessionCookie, parseCookies, SESSION_COOKIE, SESSION_STORE } from "../lib/auth.js";

export default async (request) => {
  const cookies = parseCookies(request.headers.get("cookie"));
  const sessionId = cookies[SESSION_COOKIE];

  if (sessionId) {
    const store = getStore(SESSION_STORE);
    await store.delete(sessionId);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/login.html",
      "Set-Cookie": clearSessionCookie(),
    },
  });
};
