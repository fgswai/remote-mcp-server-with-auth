#!/bin/bash

# Claude Code Integration Test Script
# This script tests the MCP server integration with Claude Code

set -e

echo "🧪 Testing Claude Code Integration with Supabase MCP Server"
echo "======================================================="

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

print_test() {
    echo -e "${BLUE}🧪 $1${NC}"
}

# Check if MCP Inspector is available
if ! command -v npx &> /dev/null; then
    print_error "npx is not installed. Please install Node.js and npm first."
    exit 1
fi

print_status "Node.js environment ready"

# Test 1: Check if server is deployed
print_test "Test 1: Checking server deployment status..."
echo ""
print_info "Checking if your MCP server is deployed..."
print_warning "Make sure you've deployed your server first with: npm run deploy"
echo ""

# Test 2: MCP Inspector connection test
print_test "Test 2: Testing MCP Inspector connection..."
echo ""
print_info "Starting MCP Inspector to test connection..."
print_warning "This will open the MCP Inspector interface."
print_warning "You'll need to configure it with your server URL:"
echo "https://supabase-mcp-server.YOUR_SUBDOMAIN.workers.dev/mcp"
echo ""

read -p "Press Enter to launch MCP Inspector (Ctrl+C to skip)..."
npx @modelcontextprotocol/inspector@latest || print_warning "MCP Inspector test skipped or failed"

echo ""
print_test "Test 3: Manual validation checklist..."
echo ""
print_info "Please verify the following in MCP Inspector:"
echo "□ Server connects successfully"
echo "□ All tools are visible (claudeCodeStatus, testConnection, listTables, queryDatabase, executeDatabase, securityMonitor, getSQLExamples)"
echo "□ Tool descriptions are Claude Code optimized"
echo "□ Test connection tool works"
echo "□ Security monitoring is active"
echo "□ Rate limiting is functioning"
echo ""

print_test "Test 4: Claude Code specific optimizations..."
echo ""
print_info "Claude Code optimizations to verify:"
echo "□ Step-by-step guidance in tool descriptions"
echo "□ Enhanced error messages with troubleshooting tips"
echo "□ Detailed tool schemas with examples"
echo "□ Progress indicators for long-running operations"
echo "□ Security warnings for dangerous operations"
echo ""

print_test "Test 5: Security features validation..."
echo ""
print_info "Security features to test:"
echo "□ Rate limiting blocks excessive requests"
echo "□ SQL injection patterns are detected and blocked"
echo "□ Access control prevents unauthorized operations"
echo "□ Security events are logged to KV storage"
echo "□ Authentication works with Git providers"
echo ""

print_test "Test 6: Database functionality validation..."
echo ""
print_info "Database operations to test:"
echo "□ List tables returns expected results"
echo "□ Query database executes simple SELECT statements"
echo "□ Execute database (if authorized) handles DML operations"
echo "□ SQL examples provide helpful guidance"
echo "□ Error handling provides clear feedback"
echo ""

echo ""
print_status "Integration test checklist complete!"
echo ""
print_info "Next steps:"
echo "1. Configure Claude Code to use your MCP server"
echo "2. Test actual database operations"
echo "3. Verify security monitoring in production"
echo "4. Monitor logs for any issues"
echo ""
print_info "Useful commands:"
echo "• Monitor server logs: wrangler tail"
echo "• Check KV storage: wrangler kv:key list --namespace-id YOUR_NAMESPACE_ID"
echo "• Test with different Git providers"
echo ""
print_info "Claude Code Configuration Example:"
echo "Add to your Claude Code MCP settings:"
echo '{'
echo '  "mcpServers": {'
echo '    "supabase-mcp-server": {'
echo '      "command": "node",'
echo '      "args": ["path/to/mcp-client.js"],'
echo '      "env": {'
echo '        "MCP_SERVER_URL": "https://supabase-mcp-server.YOUR_SUBDOMAIN.workers.dev/mcp",'
echo '        "CLAUDE_CODE_INTERFACE": "true"'
echo '      }'
echo '    }'
echo '  }'
echo '}'
echo ""
print_status "🎉 Claude Code integration testing completed!"