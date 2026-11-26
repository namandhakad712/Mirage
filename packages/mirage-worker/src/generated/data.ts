// GENERATED — do not edit; run npm run gen
// Sources: data/scanner-paths.txt, data/ua-suspicious.txt,
//          data/ua-verified-bots.txt, data/reserved-hosts.txt and
//          spec/decoy-catalog/catalog.yaml (DECOY-CATALOG.md v1).
// Scanner paths are kept EXACTLY as in the source file: trailing-slash
// insensitivity is applied at match time (SIGNALS §3.3), never here.

export const SCANNER_PATHS: string[] = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.git/config",
  "/.git/HEAD",
  "/.git/index",
  "/.aws/credentials",
  "/.ssh/id_rsa",
  "/.ssh/authorized_keys",
  "/.DS_Store",
  "/.svn/entries",
  "/.svn/wc.db",
  "/.htaccess.bak",
  "/.htpasswd",
  "/.bash_history",
  "/.mysql_history",
  "/wp-config.php.bak",
  "/wp-config.php.save",
  "/wp-config.php.old",
  "/phpmyadmin-old/",
  "/pma-old/",
  "/administrator/backups/",
  "/backup.sql",
  "/backup.zip",
  "/backup.tar.gz",
  "/db.sql",
  "/dump.sql",
  "/database.sql",
  "/database.sql.gz",
  "/site-backup.zip",
  "/web.config.bak",
  "/server-backup.tar.gz",
  "/.elastic/config/elasticsearch.yml",
  "/.docker/config.json",
  "/composer.lock.bak",
  "/package.json.bak",
  "/ids.sql",
  "/data.sql"
];

export const UA_SUSPICIOUS: string[] = [
  "sqlmap/",
  "nikto",
  "nuclei",
  "masscan",
  "zgrab",
  "nmap scripting engine",
  "python-requests/",
  "python-urllib/",
  "go-http-client/",
  "wget/",
  "libwww-perl",
  "acunetix",
  "dirbuster",
  "dirb",
  "gobuster",
  "ffuf/",
  "httpx/",
  "wpscan",
  "arachni",
  "wfuzz/",
  "havij",
  "hydra",
  "metasploit",
  "burpsuite",
  "sqlninja",
  "zap",
  "w3af"
];

export const UA_VERIFIED_BOTS: string[] = [
  "googlebot",
  "bingbot",
  "duckduckbot",
  "baiduspider",
  "yandexbot",
  "slurp"
];

// Reserved hostnames/networks all decoy content must stay within (I14).
// Carried so the worker snapshot matches the Go core's data exactly; the
// pollution/lint suite consumes it.
export const RESERVED_HOSTS: string[] = [
  "example.com",
  "example.net",
  "example.org",
  "*.test",
  "*.invalid",
  "*.example",
  "192.0.2.0/24",
  "198.51.100.0/24",
  "203.0.113.0/24"
];

// Protected routes (I4): canon policy from spec/golden-vectors/vectors.json
// (policy.protected_routes). Hardcoded so the worker stays in lockstep with
// the vectors the conformance gate replays.
export const PROTECTED_ROUTES: string[] = [
  "/wp-login.php",
  "/wp-admin/",
  "/checkout",
  "/cart",
  "/api/"
];

export interface CatalogHoneytoken {
  id: string;
  format: string;
}

export interface CatalogEntry {
  id: string;
  persona: string;
  path: string;
  status: number;
  contentType: string;
  sizeCapBytes: number;
  body: string;
  leads: string[];
  honeytokens: CatalogHoneytoken[];
}

export interface CatalogPersona {
  id: string;
  story: string;
  headers: string[];
}

export interface Catalog {
  entries: CatalogEntry[];
  personas: CatalogPersona[];
}

export const CATALOG: Catalog = {
  "entries": [
    {
      "id": "env-file-staging",
      "persona": "laravel-staging",
      "path": "/.env",
      "status": 200,
      "contentType": "text/plain",
      "sizeCapBytes": 2048,
      "body": "APP_NAME=staging\nAPP_ENV=staging\nAPP_KEY=base64:{{SEED:44_B64}}\nAPP_DEBUG=true\nAPP_URL=https://staging.example.com\n\nDB_CONNECTION=pgsql\nDATABASE_URL=postgres://deploy:{{TOKEN:db_password}}@db.test:5432/staging\nDB_USERNAME=deploy\nDB_PASSWORD={{TOKEN:db_password}}\n\nMAIL_MAILER=smtp\nMAIL_HOST=mail.test\nMAIL_PORT=1025\n\nAWS_ACCESS_KEY_ID=AKIAMRG{{SEED:13_UPPER}}\nAWS_BUCKET=staging-uploads\n",
      "leads": [
        "/storage/logs/laravel-staging.log"
      ],
      "honeytokens": [
        {
          "id": "db_password",
          "format": "token_alnum_24"
        }
      ]
    },
    {
      "id": "git-config-staging",
      "persona": "laravel-staging",
      "path": "/.git/config",
      "status": 200,
      "contentType": "text/plain",
      "sizeCapBytes": 1024,
      "body": "[core]\n    repositoryformatversion = 0\n    filemode = true\n    bare = false\n    logallrefupdates = true\n[remote \"origin\"]\n    url = https://git.test/staging/app.git\n    fetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n    remote = origin\n    merge = refs/heads/main\n",
      "leads": [
        "/.git/logs/refs/heads/main"
      ],
      "honeytokens": []
    },
    {
      "id": "admin-panel-legacy",
      "persona": "legacy-cpanel",
      "path": "/admin/login",
      "status": 200,
      "contentType": "text/html",
      "sizeCapBytes": 4096,
      "body": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <title>Admin Login</title>\n  <link rel=\"stylesheet\" href=\"/admin/assets/style.css\">\n</head>\n<body>\n  <h1>Admin Login</h1>\n  <form method=\"post\" action=\"/admin/login/verify\">\n    <label>Username <input type=\"text\" name=\"username\" autocomplete=\"off\"></label>\n    <label>Password <input type=\"password\" name=\"password\"></label>\n    <button type=\"submit\">Sign in</button>\n  </form>\n  <hr>\n  <p>Forgot password? Contact the site administrator.</p>\n</body>\n</html>\n",
      "leads": [
        "/admin/login/verify",
        "/admin/assets/style.css"
      ],
      "honeytokens": []
    },
    {
      "id": "debug-endpoint-legacy",
      "persona": "legacy-cpanel",
      "path": "/debug",
      "status": 200,
      "contentType": "application/json",
      "sizeCapBytes": 2048,
      "body": "{\n  \"app\": \"legacy-shop\",\n  \"debug\": true,\n  \"php_version\": \"7.4.33\",\n  \"session_save_path\": \"/tmp\",\n  \"opcache_enabled\": false,\n  \"last_error\": {\n    \"file\": \"/home/legacyshop/public_html/includes/db.php\",\n    \"line\": 142,\n    \"message\": \"connection refused (db.legacy.test:5432)\"\n  }\n}\n",
      "leads": [
        "/debug/phpinfo"
      ],
      "honeytokens": []
    },
    {
      "id": "api-docs-dev",
      "persona": "node-api-dev",
      "path": "/api/docs",
      "status": 200,
      "contentType": "application/json",
      "sizeCapBytes": 2048,
      "body": "{\n  \"openapi\": \"3.0.0\",\n  \"info\": { \"title\": \"internal-api\", \"version\": \"0.9.3-dev\" },\n  \"paths\": {\n    \"/v1/ping\": { \"get\": { \"summary\": \"health probe\" } },\n    \"/v1/orders\": { \"get\": { \"summary\": \"list orders\" } },\n    \"/v1/admin/tokens\": { \"post\": { \"summary\": \"issue API token\" } }\n  }\n}\n",
      "leads": [
        "/v1/admin/tokens"
      ],
      "honeytokens": []
    },
    {
      "id": "source-map-dev",
      "persona": "node-api-dev",
      "path": "/app.js.map",
      "status": 200,
      "contentType": "application/json",
      "sizeCapBytes": 2048,
      "body": "{\n  \"version\": 3,\n  \"file\": \"app.js\",\n  \"sources\": [\n    \"webpack:///src/index.js\",\n    \"webpack:///src/admin.js\",\n    \"webpack:///src/secrets.js\"\n  ],\n  \"sourcesContent\": [null, null, null]\n}\n",
      "leads": [
        "/sources/secrets.js"
      ],
      "honeytokens": []
    }
  ],
  "personas": [
    {
      "id": "laravel-staging",
      "story": "Laravel 10 on PHP 8.2 behind nginx, staging",
      "headers": [
        "Server: nginx/1.24.0",
        "X-Powered-By: PHP/8.2.12"
      ]
    },
    {
      "id": "legacy-cpanel",
      "story": "aged shared-hosting cPanel box",
      "headers": [
        "Server: Apache/2.4.6 (cPanel)",
        "X-Powered-By: PHP/7.4.33"
      ]
    },
    {
      "id": "node-api-dev",
      "story": "Node API left in dev mode",
      "headers": [
        "X-Powered-By: Express"
      ]
    }
  ]
};
