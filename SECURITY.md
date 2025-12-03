# Security Policy

## Supported Versions

We actively support the latest version of Honeypot Platform. Security updates are provided for the current release.

## Reporting a Vulnerability

If you discover a security vulnerability, please **DO NOT** open a public issue. Instead, please report it via one of the following methods:

1. **Email**: Send details via GitHub Issues or Discussions
2. **GitHub Security Advisory**: Use GitHub's private vulnerability reporting feature

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Time

We aim to respond to security reports within 48 hours and provide updates on the status of the vulnerability.

## Security Best Practices

When deploying Honeypot Platform in production:

1. **Change Default Credentials**
   - Set strong `POSTGRES_PASSWORD` via `.env` file
   - Set strong `JWT_SECRET` via `.env` file

2. **Use HTTPS**
   - Deploy behind a reverse proxy (Nginx/Apache)
   - Enable SSL/TLS certificates

3. **Network Security**
   - Use firewall rules to restrict access
   - Only expose necessary ports
   - Use VPN for remote access

4. **Regular Updates**
   - Keep Docker images updated
   - Monitor security advisories
   - Apply security patches promptly

5. **Monitoring**
   - Enable audit logging
   - Monitor for suspicious activity
   - Set up alerting

6. **Backup**
   - Regular automated backups
   - Test restore procedures
   - Store backups securely

## Disclosure Policy

- We will acknowledge receipt of your vulnerability report
- We will provide an estimated timeline for a fix
- We will notify you when the vulnerability is fixed
- We will credit you in the release notes (if desired)

Thank you for helping keep Honeypot Platform secure! 🔒

