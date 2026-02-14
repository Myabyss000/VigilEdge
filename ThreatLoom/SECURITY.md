# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatLoom, please report it responsibly:

1. **Do NOT** open a public GitHub Issue.
2. Email the maintainers directly (or use GitHub's private vulnerability reporting feature).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Security Best Practices for Deployment

- **Change default credentials** — update `DEFAULT_ADMIN_PASSWORD` in `.env` immediately.
- **Set strong secrets** — use cryptographically random values for `SECRET_KEY` and `JWT_SECRET`.
- **Use HTTPS** — deploy behind a reverse proxy (nginx, Caddy) with TLS.
- **Restrict CORS** — set `CORS_ORIGINS` to your specific frontend domains.
- **Network isolation** — run ThreatLoom on an internal network, not exposed to the public internet.
- **Regular updates** — keep dependencies up to date with `pip install -r requirements.txt --upgrade`.
