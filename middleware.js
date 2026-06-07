function unauthorized() {
  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="imusasa-hub", charset="UTF-8"',
      "Cache-Control": "no-store"
    }
  });
}

function misconfigured() {
  return new Response("Basic auth is not configured correctly.", {
    status: 500,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function decodeBasicToken(token) {
  try {
    return atob(token);
  } catch (_error) {
    return "";
  }
}

export default function middleware(request) {
  var expectedUser = process.env.BASIC_AUTH_USER || "";
  var expectedPassword = process.env.BASIC_AUTH_PASSWORD || "";

  if (!expectedUser || !expectedPassword) {
    return misconfigured();
  }

  var authHeader = request.headers.get("authorization") || "";
  if (!authHeader.startsWith("Basic ")) {
    return unauthorized();
  }

  var decoded = decodeBasicToken(authHeader.slice(6));
  var separator = decoded.indexOf(":");
  if (separator < 0) {
    return unauthorized();
  }

  var user = decoded.slice(0, separator);
  var password = decoded.slice(separator + 1);
  if (user !== expectedUser || password !== expectedPassword) {
    return unauthorized();
  }

  return fetch(request);
}

export const config = {
  matcher: "/:path*"
};
