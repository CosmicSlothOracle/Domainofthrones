import { getStore } from "@netlify/blobs";
import {
  SESSION_STORE,
  isValidPassword,
  sessionCookie,
} from "../lib/auth.js";

export default async (request) => {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  let password = "";
  const contentType = request.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    const body = await request.json().catch(() => ({}));
    password = body.password ?? "";
  } else {
    const body = await request.formData().catch(() => null);
    password = body?.get("password") ?? "";
  }

  if (!isValidPassword(password)) {
    return new Response(JSON.stringify({ ok: false, error: "Wrong passphrase." }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const sessionId = crypto.randomUUID();
  const store = getStore(SESSION_STORE);
  await store.setJSON(sessionId, {
    created: Date.now(),
  });

  return new Response(JSON.stringify({ ok: true, redirect: "/" }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": sessionCookie(sessionId),
    },
  });
};
