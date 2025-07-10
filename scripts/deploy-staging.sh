#!/bin/bash

# Staging Deployment Script for Supabase MCP Server
# This script sets up staging environment and deploys for testing

set -e  # Exit on any error

echo "🧪 Starting Staging Deployment for Supabase MCP Server"
echo "=================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    print_error "Wrangler CLI is not installed. Please install it first:"
    echo "npm install -g wrangler"
    exit 1
fi

print_status "Wrangler CLI found"

# Check if user is logged in
if ! wrangler whoami &> /dev/null; then
    print_warning "You are not logged in to Cloudflare. Please login first:"
    echo "wrangler login"
    exit 1
fi

print_status "Cloudflare authentication verified"

echo ""
print_info "Setting up staging environment..."

# Create staging KV namespaces if they don't exist
print_info "Setting up staging KV namespaces..."

if ! wrangler kv:namespace list | grep -q "OAUTH_KV_STAGING"; then
    print_warning "Creating OAUTH_KV_STAGING namespace..."
    wrangler kv:namespace create "OAUTH_KV_STAGING"
fi

if ! wrangler kv:namespace list | grep -q "SECURITY_LOGS_KV_STAGING"; then
    print_warning "Creating SECURITY_LOGS_KV_STAGING namespace..."
    wrangler kv:namespace create "SECURITY_LOGS_KV_STAGING"
fi

print_status "KV namespaces ready"

echo ""
print_info "Running type check..."
npm run type-check

if [ $? -ne 0 ]; then
    print_error "Type check failed. Please fix TypeScript errors before deploying."
    exit 1
fi

print_status "Type check passed"

echo ""
print_info "Deploying to staging..."

# Deploy to staging
wrangler deploy --config wrangler.staging.jsonc

if [ $? -eq 0 ]; then
    echo ""
    print_status "🧪 Staging deployment successful!"
    echo ""
    print_info "Your staging MCP server is now available at:"
    echo "https://supabase-mcp-server-staging.<your-subdomain>.workers.dev"
    echo ""
    print_info "Available endpoints:"
    echo "• MCP (Streamable HTTP): https://supabase-mcp-server-staging.<your-subdomain>.workers.dev/mcp"
    echo "• SSE (Legacy): https://supabase-mcp-server-staging.<your-subdomain>.workers.dev/sse"
    echo "• OAuth: https://supabase-mcp-server-staging.<your-subdomain>.workers.dev/authorize"
    echo ""
    print_info "Testing checklist:"
    echo "□ Test OAuth flow with all Git providers"
    echo "□ Test database connectivity and operations"
    echo "□ Test security features (rate limiting, validation)"
    echo "□ Test Claude Code interface optimization"
    echo "□ Test error handling and user feedback"
    echo ""
    print_info "Useful commands:"
    echo "• Monitor logs: wrangler tail supabase-mcp-server-staging"
    echo "• Test with Inspector: npx @modelcontextprotocol/inspector@latest"
    echo "• Deploy to production: npm run deploy:production"
else
    print_error "Staging deployment failed. Please check the errors above."
    exit 1
fi

echo ""
print_info "Staging deployment completed!"