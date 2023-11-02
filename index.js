import http from "node:http";
import { URL } from "node:url";
import crypto from "node:crypto";

const EDGEDB_AUTH_BASE_URL = process.env.EDGEDB_AUTH_BASE_URL;
const PORT = 3000;

const generatePKCE = () => {
  const verifier = crypto.randomBytes(32).toString("base64url");

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  return { verifier, challenge };
};

const getRequestUrl = (req) => {
  const protocol = req.connection.encrypted ? "https" : "http";
  return new URL(req.url, `${protocol}://${req.headers.host}`);
};

const server = http.createServer(async (req, res) => {
  const [pathname, search] = req.url.split("?");
  switch (pathname) {
    case "/auth/authorize": {
      await handleAuthorize(req, res);
      break;
    }

    case "/auth/callback": {
      await handleCallback(req, res);
      break;
    }

    case "/auth/signup": {
      await handleSignUp(req, res);
      break;
    }

    case "/auth/signin": {
      await handleSignIn(req, res);
      break;
    }

    case "/auth/verify": {
      await handleVerify(req, res);
      break;
    }

    default: {
      res.writeHead(404);
      res.end("Not found");
      break;
    }
  }
});

/**
 * Redirects OAuth requests to EdgeDB Auth OAuth authorize redirect
 * with the PKCE challenge, and saves PKCE verifier in an HttpOnly
 * cookie for later retrieval.
 *
 * @param {Request} req
 * @param {Response} res
 */
const handleAuthorize = async (req, res) => {
  const requestUrl = getRequestUrl(req);
  const provider = requestUrl.searchParams.get("provider");

  const pkce = generatePKCE();
  const redirectUrl = new URL("authorize", EDGEDB_AUTH_BASE_URL);
  redirectUrl.searchParams.set("provider", provider);
  redirectUrl.searchParams.set("challenge", pkce.challenge);
  redirectUrl.searchParams.set(
    "redirect_to",
    `http://localhost:{PORT}/auth/callack`
  );

  res.writeHead(301, {
    "Set-Cookie": `edgedb-pkce-verifier=${pkce.verifier}; HttpOnly`,
    Location: redirectUrl.href,
  });
  res.end();
};

/**
 * Handles the PKCE callback and exchanges the `code` and `verifier
 * for an auth_token, setting the auth_token as an HttpOnly cookie.
 *
 * @param {Request} req
 * @param {Response} res
 */
const handleCallback = async (req, res) => {
  const requestUrl = getRequestUrl(req);

  const code = requestUrl.searchParams.get("code");
  const cookies = req.headers.get("cookies")?.split("; ");
  const verifier = cookies
    .find((cookie) => cookie.startsWith("edgedb-pkce-verifier="))
    .split("=")[1];

  const codeExchangeUrl = new URL("token", EDGEDB_AUTH_BASE_URL);
  codeExchangeUrl.searchParams.set("code", code);
  codeExchangeUrl.searchParams.set("verifier", verifier);
  const codeExchangeResponse = await fetch(codeExchangeUrl.href, {
    method: "GET",
  });

  const { auth_token } = await codeExchangeResponse.json();
  res.writeHead(204, {
    "Set-Cookie": `edgedb-auth-token=${auth_token}; HttpOnly`,
  });
  res.end();
};

/**
 * Handles sign up with email and password.
 *
 * @param {Request} req
 * @param {Response} res
 */
const handleSignUp = async (req, res) => {
  let body = "";
  req.on("data", (chunk) => {
    body += chunk.toString();
  });
  req.on("end", async () => {
    const pkce = generatePKCE();
    const { email, password, provider } = JSON.parse(body);

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
        verify_url: `http://localhost:${PORT}/auth/verify`,
      }),
    });

    if (!registerResponse.ok) {
      const text = await registerResponse.text();
      console.log(`Body: ${text}`);
      res.status = 400;
      res.end(`Error from the auth server: ${text}`);
      return;
    }

    res.writeHead(204, {
      "Set-Cookie": `edgedb-pkce-verifier=${pkce.verifier}; HttpOnly`,
    });
    res.end();
  });
};
/**
 * Handles sign in with email and password.
 *
 * @param {Request} req
 * @param {Response} res
 */
const handleSignIn = async (req, res) => {
  const body = "";
  req.on("data", (chunk) => {
    body += chunk.toString();
  });
  req.on("end", async () => {
    const pkce = generatePKCE();
    const { email, password, provider } = await req.json();

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
      }),
    });

    const { code } = await authenticateResponse.json();

    const tokenUrl = new URL("token", EDGEDB_AUTH_BASE_URL);
    tokenUrl.searchParams.set("code", code);
    tokenUrl.searchParams.set("verifier", pkce.verifier);
    const tokenResponse = await fetch(tokenUrl.href, {
      method: "get",
    });

    const { auth_token } = await tokenResponse.json();
    res.writeHead(204, {
      "Set-Cookie": `edgedb-auth-token=${auth_token}; HttpOnly`,
    });
    res.end();
  });
};

/**
 * Handles the link in the email verification flow.
 *
 * @param {Request} req
 * @param {Response} res
 */
const handleVerify = async (req, res) => {
  const requestUrl = getRequestUrl(req);
  const verificationToken = requestUrl.searchParams.get("verification_token");
  const cookies = req.headers.cookie?.split("; ");
  const verifier = cookies
    .find((cookie) => cookie.startsWith("edgedb-pkce-verifier="))
    .split("=")[1];

  const verifyUrl = new URL("verify", EDGEDB_AUTH_BASE_URL);
  verifyUrl.searchParams.set("verification_token", verificationToken);
  verifyUrl.searchParams.set("verifier", verifier);
  const verifyResponse = await fetch(verifyUrl.href, {
    method: "get",
  });

  const { code } = await verifyResponse.json();

  const tokenUrl = new URL("token", EDGEDB_AUTH_BASE_URL);
  tokenUrl.searchParams.set("code", code);
  tokenUrl.searchParams.set("verifier", verifier);
  const tokenResponse = await fetch(tokenUrl.href, {
    method: "get",
  });
  const clone = tokenResponse.clone();
  console.log(`tokenResponse=${await clone.text()}`);
  const { auth_token } = await tokenResponse.json();
  res.writeHead(204, {
    "Set-Cookie": `edgedb-auth-token=${auth_token}; HttpOnly`,
  });
  res.end();
};

server.listen(PORT, () => {
  console.log(`HTTP server listening on port ${PORT}...`);
});
