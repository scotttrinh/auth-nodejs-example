import crypto from "node:crypto";

/**
 * You can get this value by running `edgedb instance credentials`.
 * Value should be: `${protocol}://${host}:${port}/db/${database}/ext/auth/
 */
const EDGEDB_AUTH_BASE_URL = process.env.EDGEDB_AUTH_BASE_URL;
const SERVER_PORT = 3000;

Bun.serve({
  port: SERVER_PORT,
  fetch: async (req) => {
    const url = new URL(req.url);

    switch (url.pathname) {
      case "/auth/ui/signin": {
        return await handleUiSignIn(req);
      }

      case "/auth/ui/signup": {
        return await handleUiSignUp(req);
      }

      case "/auth/authorize": {
        return await handleAuthorize(req);
      }

      case "/auth/callback": {
        return await handleCallback(req);
      }

      case "/auth/signup": {
        return await handleSignUp(req);
      }

      case "/auth/signin": {
        return await handleSignIn(req);
      }

      case "/auth/verify": {
        return await handleVerify(req);
      }

      default: {
        return new Response("Not found", { status: 404 });
      }
    }
  },
});

/**
 * Redirects browser requests to EdgeDB Auth UI sign in page with the
 * PKCE challenge, and saves PKCE verifier in an HttpOnly cookie.
 */
async function handleUiSignIn(_req: Request) {
  const pkce = generatePKCE();
  const redirectUrl = new URL("ui/signin", EDGEDB_AUTH_BASE_URL);
  redirectUrl.searchParams.set("challenge", pkce.challenge);

  return new Response(null, {
    status: 302,
    headers: {
      location: redirectUrl.href,
      "set-cookie": `edgedb-pkce-verifier=${pkce.verifier}; HttpOnly; Path=/; Secure; SameSite=Strict`,
    },
  });
}

/**
 * Redirects browser requests to EdgeDB Auth UI sign up page with the
 * PKCE challenge, and saves PKCE verifier in an HttpOnly cookie.
 */
async function handleUiSignUp(_req: Request) {
  const pkce = generatePKCE();
  const redirectUrl = new URL("ui/signup", EDGEDB_AUTH_BASE_URL);
  redirectUrl.searchParams.set("challenge", pkce.challenge);

  return new Response(null, {
    status: 302,
    headers: {
      location: redirectUrl.href,
      "set-cookie": `edgedb-pkce-verifier=${pkce.verifier}; HttpOnly; Path=/; Secure; SameSite=Strict`,
    },
  });
}

/**
 * Redirects OAuth requests to EdgeDB Auth OAuth authorize redirect
 * with the PKCE challenge, and saves PKCE verifier in an HttpOnly
 * cookie for later retrieval.
 */
async function handleAuthorize(req: Request) {
  const url = new URL(req.url);
  const provider = url.searchParams.get("provider");

  if (!provider) {
    return new Response(
      "Must provide a 'provider' value in search parameters",
      { status: 400 },
    );
  }

  const pkce = generatePKCE();
  const redirectUrl = new URL("authorize", EDGEDB_AUTH_BASE_URL);
  redirectUrl.searchParams.set("provider", provider);
  redirectUrl.searchParams.set("challenge", pkce.challenge);
  redirectUrl.searchParams.set(
    "redirect_to",
    `http://localhost:${SERVER_PORT}/auth/callack`,
  );

  return new Response(null, {
    status: 302,
    headers: {
      location: redirectUrl.href,
      "set-cookie": `edgedb-pkce-verifier=${pkce.verifier}; HttpOnly; Path=/; Secure; SameSite=Strict`,
    },
  });
}

/**
 * Handles the PKCE callback and exchanges the `code` and `verifier
 * for an auth_token, setting the auth_token as an HttpOnly cookie.
 */
async function handleCallback(req: Request) {
  const url = new URL(req.url);

  const code = url.searchParams.get("code");
  if (!code) {
    const error = url.searchParams.get("error");
    return new Response(
      `OAuth callback is missing 'code'. OAuth provider responded with error: ${error}`,
      { status: 400 },
    );
  }

  const cookies = req.headers.get("cookie")?.split("; ");
  const verifier = cookies
    ?.find((cookie) => cookie.startsWith("edgedb-pkce-verifier="))
    ?.split("=")[1];
  if (!verifier) {
    return new Response(
      `Could not find 'verifier' in the cookie store. Is this the same user agent/browser that started the authorization flow?`,
      { status: 400 },
    );
  }

  const codeExchangeUrl = new URL("token", EDGEDB_AUTH_BASE_URL);
  codeExchangeUrl.searchParams.set("code", code);
  codeExchangeUrl.searchParams.set("verifier", verifier);
  const codeExchangeResponse = await fetch(codeExchangeUrl.href, {
    method: "GET",
  });

  if (!codeExchangeResponse.ok) {
    const text = await codeExchangeResponse.text();
    return new Response(`Error from the auth server: ${text}`, { status: 400 });
  }

  const { auth_token } = await codeExchangeResponse.json();
  return new Response(null, {
    status: 204,
    headers: {
      "set-cookie": `edgedb-auth-token=${auth_token}; Path=/; HttpOnly`,
    },
  });
}

/**
 * Handles sign up with email and password.
 */
async function handleSignUp(req: Request) {
  const body = await req.json();
  const { email, password, provider } = body;
  if (!email || !password || !provider) {
    return new Response(
      `Request body malformed. Expected JSON body with 'email', 'password', and 'provider' keys, but got: ${body}`,
      { status: 400 },
    );
  }
  const pkce = generatePKCE();

  const registerUrl = new URL("register", EDGEDB_AUTH_BASE_URL);
  const registerResponse = await fetch(registerUrl.href, {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      challenge: pkce.challenge,
      email,
      password,
      provider,
      verify_url: `http://localhost:${SERVER_PORT}/auth/verify`,
    }),
  });

  if (!registerResponse.ok) {
    const text = await registerResponse.text();
    return new Response(`Error from the auth server: ${text}`, { status: 400 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      "set-cookie": `edgedb-pkce-verifier=${pkce.verifier}; HttpOnly; Path=/; Secure; SameSite=Strict`,
    },
  });
}

/**
 * Handles sign in with email and password.
 */
async function handleSignIn(req: Request) {
  const body = await req.json();
  const { email, password, provider } = body;
  if (!email || !password || !provider) {
    return new Response(
      `Request body malformed. Expected JSON body with 'email', 'password', and 'provider' keys, but got: ${body}`,
      { status: 400 },
    );
  }
  const pkce = generatePKCE();

  const authenticateUrl = new URL("authenticate", EDGEDB_AUTH_BASE_URL);
  const authenticateResponse = await fetch(authenticateUrl.href, {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      challenge: pkce.challenge,
      email,
      password,
      provider,
      verify_url: `http://localhost:${SERVER_PORT}/auth/verify`,
    }),
  });

  if (!authenticateResponse.ok) {
    const text = await authenticateResponse.text();
    return new Response(`Error from the auth server: ${text}`, { status: 400 });
  }

  const { code } = await authenticateResponse.json();

  const tokenUrl = new URL("token", EDGEDB_AUTH_BASE_URL);
  tokenUrl.searchParams.set("code", code);
  tokenUrl.searchParams.set("verifier", pkce.verifier);
  const tokenResponse = await fetch(tokenUrl.href, {
    method: "get",
  });

  if (!tokenResponse.ok) {
    const text = await authenticateResponse.text();
    return new Response(`Error from the auth server: ${text}`, { status: 400 });
  }

  const { auth_token } = await tokenResponse.json();
  return new Response(null, {
    status: 204,
    headers: {
      "set-cookie": `edgedb-auth-token=${auth_token}; HttpOnly; Path=/; Secure; SameSite=Strict`,
    },
  });
}

/**
 * Handles the link in the email verification flow.
 */
async function handleVerify(req: Request) {
  const url = new URL(req.url);
  const verification_token = url.searchParams.get("verification_token");
  if (!verification_token) {
    return new Response(
      `Verify request is missing 'verification_token' search param. The verification email is malformed.`,
      { status: 400 },
    );
  }

  const cookies = req.headers.get("cookie")?.split("; ");
  const verifier = cookies
    ?.find((cookie) => cookie.startsWith("edgedb-pkce-verifier="))
    ?.split("=")[1];
  if (!verifier) {
    return new Response(
      `Could not find 'verifier' in the cookie store. Is this the same user agent/browser that started the authorization flow?`,
      { status: 400 },
    );
  }

  const verifyUrl = new URL("verify", EDGEDB_AUTH_BASE_URL);
  const verifyResponse = await fetch(verifyUrl.href, {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      verification_token,
      verifier,
      provider: "builtin::local_emailpassword",
    }),
  });

  if (!verifyResponse.ok) {
    const text = await verifyResponse.text();
    return new Response(`Error from the auth server: ${text}`, { status: 400 });
  }

  const { code } = await verifyResponse.json();

  const tokenUrl = new URL("token", EDGEDB_AUTH_BASE_URL);
  tokenUrl.searchParams.set("code", code);
  tokenUrl.searchParams.set("verifier", verifier);
  const tokenResponse = await fetch(tokenUrl.href, {
    method: "get",
  });

  if (!tokenResponse.ok) {
    const text = await tokenResponse.text();
    return new Response(`Error from the auth server: ${text}`, { status: 400 });
  }

  const { auth_token } = await tokenResponse.json();
  return new Response(null, {
    status: 204,
    headers: {
      "set-cookie": `edgedb-auth-token=${auth_token}; HttpOnly; Path=/; Secure; SameSite=Strict`,
    },
  });
}

/**
 * Generate a random Base64 url-encoded string, and derive a "challenge"
 * string from that string to use as proof that the request for a token
 * later is made from the same user agent that made the original request
 */
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  return { verifier, challenge };
}
