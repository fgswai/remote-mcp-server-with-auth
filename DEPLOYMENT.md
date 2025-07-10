# Supabase MCP Server Deployment Guide

This guide covers deploying the Supabase MCP Server with Claude Code integration, Git authentication, and Cloudflare Workers.

## Prerequisites

- Node.js (v18 or higher)
- Cloudflare account with Workers enabled
- Supabase account and project
- Git provider account (GitHub, GitLab, or Bitbucket)
- OAuth application configured on your Git provider

## Quick Start

1. **Clone and install dependencies**:
   ```bash
   git clone https://github.com/your-repo/remote-mcp-server-with-auth.git
   cd remote-mcp-server-with-auth
   npm install
   ```

2. **Configure environment variables**:
   ```bash
   cp .dev.vars.example .dev.vars
   # Edit .dev.vars with your configuration
   ```

3. **Deploy to production**:
   ```bash
   npm run deploy:production
   ```

## Detailed Setup

### 1. Supabase Configuration

1. Create a new Supabase project at https://supabase.com
2. Get your database connection string from Project Settings > Database
3. Ensure Row Level Security (RLS) is enabled
4. Configure your database schema as needed

### 2. Git OAuth Application Setup

#### GitHub
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App with:
   - Homepage URL: `https://your-domain.workers.dev`
   - Authorization callback URL: `https://your-domain.workers.dev/callback`

#### GitLab
1. Go to GitLab User Settings > Applications
2. Create a new application with:
   - Redirect URI: `https://your-domain.workers.dev/callback`
   - Scopes: `read_user`

#### Bitbucket
1. Go to Bitbucket Settings > OAuth
2. Create a new consumer with:
   - Callback URL: `https://your-domain.workers.dev/callback`
   - Permissions: Account Read

### 3. Cloudflare Workers Setup

1. **Install Wrangler CLI**:
   ```bash
   npm install -g wrangler
   ```

2. **Login to Cloudflare**:
   ```bash
   wrangler login
   ```

3. **Create KV namespaces**:
   ```bash
   npm run setup:kv
   ```

4. **Update wrangler.jsonc** with your KV namespace IDs

### 4. Environment Variables

Create a `.dev.vars` file with the following variables:

```bash
# Required
GIT_CLIENT_ID=your_git_oauth_client_id
GIT_CLIENT_SECRET=your_git_oauth_client_secret
GIT_PROVIDER=github  # or gitlab, bitbucket
DATABASE_URL=your_supabase_connection_string
COOKIE_ENCRYPTION_KEY=your_32_char_encryption_key

# Optional
SENTRY_DSN=your_sentry_dsn
CLAUDE_CODE_INTERFACE=true
```

### 5. Production Deployment

Use the automated deployment script:

```bash
npm run deploy:production
```

Or deploy manually:

```bash
# Set secrets
wrangler secret put GIT_CLIENT_ID
wrangler secret put GIT_CLIENT_SECRET
wrangler secret put GIT_PROVIDER
wrangler secret put DATABASE_URL
wrangler secret put COOKIE_ENCRYPTION_KEY

# Deploy
wrangler deploy
```

## Testing

### 1. Basic Connectivity Test

```bash
npm run test:connection
```

### 2. Claude Code Integration Test

```bash
npm run test:claude
```

### 3. Manual Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector@latest --url https://your-domain.workers.dev/mcp
```

## Claude Code Configuration

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "supabase-mcp-server": {
      "command": "node",
      "args": ["-e", "/* connection script */"],
      "env": {
        "MCP_SERVER_URL": "https://your-domain.workers.dev/mcp",
        "CLAUDE_CODE_INTERFACE": "true"
      }
    }
  }
}
```

## Security Features

### Rate Limiting
- 60 requests per minute for general operations
- 30 requests per minute for database queries
- 10 requests per minute for database executions
- 5 authentication attempts per 5 minutes

### Input Validation
- SQL injection protection
- XSS prevention
- Input length limits
- Dangerous pattern detection

### Access Control
- User-based permissions
- Operation-specific access control
- Security event logging
- Suspicious activity detection

## Monitoring

### View Logs
```bash
# Production logs
wrangler tail

# Staging logs
wrangler tail supabase-mcp-server-staging
```

### Security Events
Security events are logged to KV storage and can be retrieved using the security monitoring tools.

### Performance Monitoring
- Request timing
- Error rates
- Rate limit hits
- Database performance

## Troubleshooting

### Common Issues

1. **Database Connection Errors**:
   - Verify DATABASE_URL is correct
   - Check Supabase project status
   - Ensure SSL connections are enabled

2. **Authentication Failures**:
   - Verify OAuth app configuration
   - Check callback URLs match
   - Ensure client ID and secret are correct

3. **Rate Limiting Issues**:
   - Check request frequency
   - Review rate limit configuration
   - Monitor security logs

4. **Claude Code Integration Issues**:
   - Verify CLAUDE_CODE_INTERFACE=true
   - Check MCP server URL configuration
   - Test with MCP Inspector first

### Debug Mode

Enable debug logging:
```bash
wrangler dev --local
```

### KV Storage Debugging

List KV entries:
```bash
wrangler kv:key list --namespace-id YOUR_NAMESPACE_ID
```

## Staging Environment

Deploy to staging for testing:

```bash
npm run deploy:staging
```

## Production Checklist

Before deploying to production:

- [ ] All environment variables configured
- [ ] KV namespaces created and configured
- [ ] OAuth application configured correctly
- [ ] Database connection tested
- [ ] Security settings reviewed
- [ ] Rate limits configured appropriately
- [ ] Monitoring and logging enabled
- [ ] Backup and recovery plan in place

## Support

- Check the logs: `wrangler tail`
- Test with MCP Inspector
- Review security events in KV storage
- Monitor Cloudflare Workers analytics
- Check Supabase project health

## Performance Optimization

- Use connection pooling (already configured)
- Monitor database query performance
- Optimize SQL queries
- Cache frequently accessed data
- Use appropriate rate limits

## Scaling

- Monitor worker usage
- Adjust rate limits as needed
- Scale KV namespace usage
- Monitor database connections
- Consider database read replicas for heavy read workloads