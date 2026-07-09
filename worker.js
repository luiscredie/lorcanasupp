// Ranger Atlas save server — Cloudflare Worker.
// Holds your GitHub token as a SECRET so no browser ever sees it.

const CFG = (env) => ({
  owner: env.GH_OWNER || "luiscredie",
  repo: env.GH_REPO || "lorcana",
  branch: env.GH_BRANCH || "main",
  path: env.GH_PATH || "atlas-data.json",
});

const ALLOW = "https://luiscredie.github.io";

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": ALLOW === "*" ? (origin || "*") : ALLOW,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function json(obj, status, origin) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...cors(origin),
    },
  });
}

function decodeGithubBase64(content) {
  const clean = String(content || "").replace(/\s/g, "");
  return decodeURIComponent(escape(atob(clean)));
}

function encodeGithubBase64(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors(origin),
      });
    }

    const c = CFG(env);

    const api =
      "https://api.github.com/repos/" +
      c.owner +
      "/" +
      c.repo +
      "/contents/" +
      c.path;

    const ghHeaders = (extra) => ({
      Authorization: "Bearer " + env.GH_TOKEN,
      Accept: "application/vnd.github+json",
      "User-Agent": "ranger-atlas-worker",
      ...(extra || {}),
    });

    try {
      if (request.method === "GET") {
        if (!env.GH_TOKEN) {
          return json(
            { error: "server missing GH_TOKEN secret" },
            500,
            origin
          );
        }

        const r = await fetch(api + "?ref=" + c.branch + "&t=" + Date.now(), {
          headers: ghHeaders(),
        });

        if (r.status === 404) {
          return json({ doc: null, sha: null }, 200, origin);
        }

        if (!r.ok) {
          return json({ error: "read " + r.status }, 502, origin);
        }

        const j = await r.json();

        let doc = null;
        try {
          doc = JSON.parse(decodeGithubBase64(j.content));
        } catch (e) {
          return json(
            { error: "could not parse atlas-data.json as JSON" },
            500,
            origin
          );
        }

        return json({ doc, sha: j.sha }, 200, origin);
      }

      if (request.method === "POST") {
        if (!env.GH_TOKEN) {
          return json(
            { error: "server missing GH_TOKEN secret" },
            500,
            origin
          );
        }

        const body = await request.json().catch(() => ({}));

        if (typeof body.content !== "string") {
          return json({ error: "no content" }, 400, origin);
        }

        // Validate before writing.
        try {
          JSON.parse(body.content);
        } catch (e) {
          return json({ error: "content is not valid JSON" }, 400, origin);
        }

        const put = {
          message: "Ranger Atlas sync " + new Date().toISOString(),
          content: encodeGithubBase64(body.content),
          branch: c.branch,
        };

        if (body.sha) {
          put.sha = body.sha;
        }

        const r = await fetch(api, {
          method: "PUT",
          headers: ghHeaders({
            "Content-Type": "application/json",
          }),
          body: JSON.stringify(put),
        });

        if (r.status === 409 || r.status === 422) {
          return json({ error: "conflict" }, 409, origin);
        }

        if (!r.ok) {
          const t = await r.text();
          return json(
            { error: "write " + r.status + " " + t.slice(0, 300) },
            502,
            origin
          );
        }

        const j = await r.json();

        return json(
          {
            ok: true,
            sha: j.content && j.content.sha,
          },
          200,
          origin
        );
      }

      return json({ error: "method" }, 405, origin);
    } catch (e) {
      return json(
        {
          error: String((e && e.message) || e),
        },
        500,
        origin
      );
    }
  },
};