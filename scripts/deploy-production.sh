#!/bin/bash

# Production Deployment Script for Supabase MCP Server
# This script sets up all required environment variables and deploys to production

set -e  # Exit on any error

echo "🚀 Starting Production Deployment for Supabase MCP Server"
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

# Function to check if secret exists
check_secret() {
    local secret_name=$1
    if wrangler secret list | grep -q "$secret_name"; then
        return 0
    else
        return 1
    fi
}

# Function to set secret
set_secret() {
    local secret_name=$1
    local secret_description=$2
    
    if check_secret "$secret_name"; then
        print_warning "Secret $secret_name already exists. Update it? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "$secret_description"
            wrangler secret put "$secret_name"
        else
            print_info "Skipping $secret_name"
        fi
    else
        echo "$secret_description"
        wrangler secret put "$secret_name"
    fi
}

echo ""
print_info "Setting up production secrets..."
echo ""

# Set up required secrets
set_secret "GIT_CLIENT_ID" "Enter your Git provider OAuth Client ID (GitHub/GitLab/Bitbucket):"
set_secret "GIT_CLIENT_SECRET" "Enter your Git provider OAuth Client Secret:"
set_secret "GIT_PROVIDER" "Enter your Git provider (github/gitlab/bitbucket):"
set_secret "DATABASE_URL" "Enter your Supabase database connection string:"
set_secret "COOKIE_ENCRYPTION_KEY" "Enter cookie encryption key (generate with: openssl rand -hex 32):"

# Optional secrets
print_info "Optional secrets (press Enter to skip):"
set_secret "SENTRY_DSN" "Enter Sentry DSN for error monitoring (optional):"

echo ""
print_info "Checking KV namespaces..."

# Check if KV namespaces exist
if ! wrangler kv:namespace list | grep -q "OAUTH_KV"; then
    print_warning "Creating OAUTH_KV namespace..."
    wrangler kv:namespace create "OAUTH_KV"
    print_warning "Please update wrangler.jsonc with the new namespace ID"
fi

if ! wrangler kv:namespace list | grep -q "SECURITY_LOGS_KV"; then
    print_warning "Creating SECURITY_LOGS_KV namespace..."
    wrangler kv:namespace create "SECURITY_LOGS_KV"
    print_warning "Please update wrangler.jsonc with the new namespace ID"
fi

echo ""
print_info "Running type check..."
npm run type-check

if [ $? -ne 0 ]; then
    print_error "Type check failed. Please fix TypeScript errors before deploying."
    exit 1
fi

print_status "Type check passed"

echo ""
print_info "Deploying to production..."

# Deploy to production
wrangler deploy

if [ $? -eq 0 ]; then
    echo ""
    print_status "🎉 Production deployment successful!"
    echo ""
    print_info "Your MCP server is now available at:"
    echo "https://supabase-mcp-server.<your-subdomain>.workers.dev"
    echo ""
    print_info "Available endpoints:"
    echo "• MCP (Streamable HTTP): https://supabase-mcp-server.<your-subdomain>.workers.dev/mcp"
    echo "• SSE (Legacy): https://supabase-mcp-server.<your-subdomain>.workers.dev/sse"
    echo "• OAuth: https://supabase-mcp-server.<your-subdomain>.workers.dev/authorize"
    echo ""
    print_info "Next steps:"
    echo "1. Update your Git OAuth app callback URL to match the deployed domain"
    echo "2. Test the deployment with MCP Inspector"
    echo "3. Configure Claude Code to use your MCP server"
    echo "4. Monitor logs with: wrangler tail"
else
    print_error "Deployment failed. Please check the errors above."
    exit 1
fi

echo ""
print_info "Deployment completed!"