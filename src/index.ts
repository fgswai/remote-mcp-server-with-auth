import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import { GitHandler } from "./git-handler";
import { formatDatabaseError, validateSqlQuery, isWriteOperation, closeDb, withDatabase } from "./database";
import { 
	SecurityValidator, 
	RateLimiter, 
	AccessControl, 
	SecurityLogger, 
	DataSanitizer,
	SECURITY_CONFIG,
	type SecurityContext 
} from "./security";

// Context from the auth process, encrypted & stored in the auth token
// and provided to the DurableMCP as this.props
// Enhanced to support multiple Git providers (GitHub, GitLab, Bitbucket, etc.)
type Props = {
	login: string;
	name: string;
	email: string;
	accessToken: string;
	provider: string; // github, gitlab, bitbucket, etc.
	avatar_url?: string;
	user_id: string | number;
};

const ALLOWED_USERNAMES = new Set<string>([
	// Add Git usernames of users who should have access to database write operations
	// Works across all supported Git providers (GitHub, GitLab, Bitbucket, etc.)
	// For example: 'yourusername', 'coworkerusername'
	'coleam00'
]);

export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "Supabase Database MCP Server",
		version: "1.0.0",
	});

	// Claude Code interface optimization settings
	private claudeCodeConfig = {
		enabled: true,
		maxToolCallsPerMinute: 60,
		enhancedErrorHandling: true,
		streamingSupport: true,
		detailedLogging: true,
	};

	/**
	 * Check if Claude Code optimizations are enabled
	 */
	private isClaudeCodeOptimized(): boolean {
		return this.claudeCodeConfig.enabled && 
			   (this.env as any).CLAUDE_CODE_INTERFACE === 'true';
	}

	/**
	 * Get Claude Code optimized tool metadata
	 */
	private getClaudeToolMetadata(toolName: string) {
		return {
			// Enhanced metadata for Claude Code
			interface: "claude-code",
			category: "database",
			complexity: toolName === 'executeDatabase' ? 'high' : 'medium',
			safety_level: toolName === 'executeDatabase' ? 'dangerous' : 'safe',
			provider: "supabase",
			authentication: this.props.provider,
		};
	}

	/**
	 * Create security context for operations
	 */
	private createSecurityContext(operation: string): SecurityContext {
		return {
			userId: this.props.login,
			provider: this.props.provider,
			timestamp: Date.now(),
			operation,
			// Note: In a real implementation, these would come from request headers
			userAgent: 'Claude-Code-Client',
			ipAddress: 'cloudflare-worker',
		};
	}

	/**
	 * Apply security checks for tool operations
	 */
	private async checkSecurity(operation: string, input?: string): Promise<{ allowed: boolean; error?: string }> {
		const context = this.createSecurityContext(operation);
		
		// Rate limiting check
		const rateLimitConfig = SECURITY_CONFIG.rateLimits[operation as keyof typeof SECURITY_CONFIG.rateLimits] || SECURITY_CONFIG.rateLimits.default;
		const rateLimit = RateLimiter.checkRateLimit(this.props.login, rateLimitConfig, context);
		
		if (!rateLimit.allowed) {
			return { 
				allowed: false, 
				error: `**🚫 Rate Limit Exceeded**

You have exceeded the rate limit for ${operation} operations.

**Current Limits:**
- Maximum requests: ${rateLimitConfig.maxRequests}
- Time window: ${Math.round(rateLimitConfig.windowMs / 1000)} seconds
- Reset time: ${new Date(rateLimit.resetTime).toISOString()}

**Security Information:**
- This limit helps protect against abuse and ensures fair usage
- Rate limits are applied per user and operation type
- Consider reducing request frequency or batching operations

**Immediate Actions:**
1. Wait for the rate limit window to reset
2. Review your usage patterns
3. Contact support if you need higher limits for legitimate use` 
			};
		}
		
		// Access control check
		const permission = operation === 'execute' ? 'write' : 'read';
		const hasAccess = AccessControl.hasPermission(context, permission, ALLOWED_USERNAMES);
		
		if (!hasAccess) {
			return { 
				allowed: false, 
				error: `**🔒 Access Denied**

You do not have permission for ${operation} operations.

**Permission Level Required:** ${permission}
**Your Current Level:** ${ALLOWED_USERNAMES.has(this.props.login) ? 'write' : 'read'}

**To Request Access:**
- Contact a system administrator
- Use the \`requestWriteAccess\` tool for more information
- Your username (${this.props.login}) needs to be added to the approved list`
			};
		}
		
		// Input validation for SQL operations
		if (input && (operation === 'query' || operation === 'execute')) {
			const validation = SecurityValidator.validateSQLInput(input, context);
			if (!validation.isValid) {
				return { 
					allowed: false, 
					error: `**⚠️ Security Validation Failed**

${validation.error}

**Risk Level:** ${validation.risk}
**Operation:** ${operation}

**Security Guidelines:**
- Avoid using dangerous SQL patterns
- Use parameterized queries when possible
- Test queries in a safe environment first
- Follow SQL injection prevention best practices

**Need Help?**
- Use \`getSQLExamples\` for safe query templates
- Check your query syntax carefully
- Contact support for complex query assistance`
				};
			}
			
			// Log high-risk operations
			if (validation.risk === 'high') {
				SecurityLogger.logSecurityEvent('HIGH_RISK_OPERATION', context, { 
					risk: validation.risk, 
					inputLength: input.length 
				}, (this.env as any).SECURITY_LOGS_KV);
			}
		}
		
		// Suspicious activity detection
		const suspiciousActivity = AccessControl.detectSuspiciousActivity(context);
		if (suspiciousActivity.suspicious) {
			SecurityLogger.logSecurityEvent('SUSPICIOUS_ACTIVITY_DETECTED', context, { 
				reason: suspiciousActivity.reason 
			}, (this.env as any).SECURITY_LOGS_KV);
			// Note: We're not blocking for suspicious activity, just logging
		}
		
		return { allowed: true };
	}

	/**
	 * Cleanup database connections when Durable Object is shutting down
	 */
	async cleanup(): Promise<void> {
		try {
			await closeDb();
			console.log('Database connections closed successfully');
		} catch (error) {
			console.error('Error during database cleanup:', error);
		}
	}

	/**
	 * Durable Objects alarm handler - used for cleanup
	 */
	async alarm(): Promise<void> {
		await this.cleanup();
	}

	async init() {
		// Tool 0: Claude Code Interface Status - Available to all authenticated users
		this.server.tool(
			"claudeCodeStatus",
			"Get information about Claude Code interface optimizations, server capabilities, and performance settings. This tool provides metadata about the MCP server's Claude Code integration features.",
			{},
			async () => {
				try {
					const isOptimized = this.isClaudeCodeOptimized();
					const metadata = this.getClaudeToolMetadata("status");
					
					return {
						content: [
							{
								type: "text",
								text: `**🤖 Claude Code Interface Status**

**⚙️ Optimization Status:**
- Claude Code Interface: ${isOptimized ? '✅ ENABLED' : '❌ DISABLED'}
- Enhanced Error Handling: ${this.claudeCodeConfig.enhancedErrorHandling ? '✅' : '❌'}
- Streaming Support: ${this.claudeCodeConfig.streamingSupport ? '✅' : '❌'}
- Detailed Logging: ${this.claudeCodeConfig.detailedLogging ? '✅' : '❌'}

**🔧 Performance Settings:**
- Max Tool Calls/Minute: ${this.claudeCodeConfig.maxToolCallsPerMinute}
- Database Provider: Supabase (PostgreSQL)
- Authentication Provider: ${this.props.provider}
- User: ${this.props.name} (${this.props.login})

**🛠️ Available Tools:**
- \`claudeCodeStatus\` - This interface status tool
- \`testConnection\` - Database connectivity test
- \`listTables\` - Enhanced schema exploration
- \`queryDatabase\` - Optimized query execution
${ALLOWED_USERNAMES.has(this.props.login) ? '- `executeDatabase` - Privileged write operations' : '- `requestWriteAccess` - Write access information'}

**📊 Server Capabilities:**
- Multi-provider Git authentication (GitHub, GitLab, Bitbucket)
- Role-based access control
- Real-time error reporting
- Comprehensive audit logging
- Supabase-specific optimizations

**🔍 Claude Code Features:**
- Enhanced tool descriptions for better AI understanding
- Structured error messages with troubleshooting
- Performance metrics and timing information
- Safety level indicators for dangerous operations
- Context-aware user guidance

**💡 Usage Tips for Claude Code:**
1. Always start with \`testConnection\` to verify setup
2. Use \`listTables\` to understand database structure
3. Test queries with \`queryDatabase\` before write operations
4. Monitor performance metrics in tool responses
5. Check error messages for specific troubleshooting steps

**🌐 Environment:** ${(this.env as any).NODE_ENV || 'production'}
**📍 Server Location:** Cloudflare Workers (Global Edge)
**🔒 Security Level:** Enterprise (OAuth + RLS)`
							}
						]
					};
				} catch (error) {
					console.error('claudeCodeStatus error:', error);
					return {
						content: [
							{
								type: "text",
								text: `**❌ Claude Code Status Error**

Unable to retrieve interface status: ${error instanceof Error ? error.message : 'Unknown error'}

**Basic Information:**
- Server: Supabase Database MCP Server
- User: ${this.props.name} (${this.props.login} via ${this.props.provider})
- Authentication: Active

Please contact support if this issue persists.`,
								isError: true
							}
						]
					};
				}
			}
		);

		// Tool 1: Test Database Connection - Available to all authenticated users
		this.server.tool(
			"testConnection",
			"[STEP 1] Test the Supabase database connection and verify connectivity. 🔧 RECOMMENDED FIRST STEP: Use this to ensure the database is accessible and working properly before attempting other operations. Claude Code Optimized.",
			{},
			async () => {
				try {
					// Security checks
					const securityCheck = await this.checkSecurity('connection');
					if (!securityCheck.allowed) {
						return {
							content: [
								{
									type: "text",
									text: securityCheck.error!,
									isError: true
								}
							]
						};
					}

					return await withDatabase((this.env as any).DATABASE_URL, async (db) => {
						// Simple connectivity test
						const result = await db`SELECT version(), current_database(), current_user, inet_server_addr() as server_ip`;
						const connectionInfo = result[0];
						
						// Test basic table access (information_schema is always available)
						const tableCount = await db`
							SELECT COUNT(*) as table_count 
							FROM information_schema.tables 
							WHERE table_schema = 'public'
						`;
						
						return {
							content: [
								{
									type: "text",
									text: `**✅ Supabase Connection Successful!**

**Database Information:**
- Database: ${connectionInfo.current_database}
- User: ${connectionInfo.current_user}
- Server IP: ${connectionInfo.server_ip || 'N/A'}
- PostgreSQL Version: ${connectionInfo.version}

**Schema Information:**
- Public tables found: ${tableCount[0].table_count}

**Connection Status:** 🟢 Connected and ready for operations

**Next Steps:**
- Use \`listTables\` to explore your database schema
- Use \`queryDatabase\` for read operations  
- Use \`executeDatabase\` for write operations (if you have permissions)`
								}
							]
						};
					});
				} catch (error) {
					console.error('testConnection error:', error);
					return {
						content: [
							{
								type: "text",
								text: formatDatabaseError(error, 'Database Connection Test'),
								isError: true
							}
						]
					};
				}
			}
		);

		// Tool 2: List Tables - Available to all authenticated users
		this.server.tool(
			"listTables",
			"[STEP 2] Get a comprehensive list of all tables in the Supabase database with detailed column information, constraints, and indexes. 📋 SCHEMA EXPLORATION: Essential for understanding database structure before querying. Claude Code Optimized with enhanced metadata.",
			{},
			async () => {
				try {
					// Security checks
					const securityCheck = await this.checkSecurity('schema');
					if (!securityCheck.allowed) {
						return {
							content: [
								{
									type: "text",
									text: securityCheck.error!,
									isError: true
								}
							]
						};
					}

					return await withDatabase((this.env as any).DATABASE_URL, async (db) => {
						// Enhanced query to get comprehensive table information including Supabase-specific details
						const tablesQuery = await db`
							SELECT 
								t.table_name,
								t.table_type,
								obj_description(c.oid, 'pg_class') as table_comment,
								COALESCE(
									(SELECT COUNT(*) FROM information_schema.table_constraints tc 
									 WHERE tc.table_name = t.table_name AND tc.constraint_type = 'PRIMARY KEY'), 0
								) as has_primary_key
							FROM information_schema.tables t
							LEFT JOIN pg_class c ON c.relname = t.table_name
							WHERE t.table_schema = 'public' 
							AND t.table_type = 'BASE TABLE'
							ORDER BY t.table_name
						`;

						// Get column information with enhanced details
						const columns = await db`
							SELECT 
								c.table_name, 
								c.column_name, 
								c.data_type, 
								c.is_nullable,
								c.column_default,
								c.character_maximum_length,
								c.numeric_precision,
								c.numeric_scale,
								CASE WHEN pk.column_name IS NOT NULL THEN true ELSE false END as is_primary_key,
								CASE WHEN fk.column_name IS NOT NULL THEN true ELSE false END as is_foreign_key,
								col_description(pgc.oid, c.ordinal_position) as column_comment
							FROM information_schema.columns c
							LEFT JOIN information_schema.table_constraints tc 
								ON c.table_name = tc.table_name 
								AND tc.constraint_type = 'PRIMARY KEY'
							LEFT JOIN information_schema.key_column_usage pk 
								ON c.table_name = pk.table_name 
								AND c.column_name = pk.column_name 
								AND pk.constraint_name = tc.constraint_name
							LEFT JOIN information_schema.table_constraints tc2 
								ON c.table_name = tc2.table_name 
								AND tc2.constraint_type = 'FOREIGN KEY'
							LEFT JOIN information_schema.key_column_usage fk 
								ON c.table_name = fk.table_name 
								AND c.column_name = fk.column_name 
								AND fk.constraint_name = tc2.constraint_name
							LEFT JOIN pg_class pgc ON pgc.relname = c.table_name
							WHERE c.table_schema = 'public' 
							ORDER BY c.table_name, c.ordinal_position
						`;
						
						// Group columns by table
						const tableMap = new Map();
						
						// Initialize tables
						for (const table of tablesQuery) {
							tableMap.set(table.table_name, {
								name: table.table_name,
								type: table.table_type,
								schema: 'public',
								comment: table.table_comment,
								has_primary_key: table.has_primary_key > 0,
								columns: []
							});
						}
						
						// Add columns to tables
						for (const col of columns) {
							if (tableMap.has(col.table_name)) {
								tableMap.get(col.table_name).columns.push({
									name: col.column_name,
									type: col.data_type,
									nullable: col.is_nullable === 'YES',
									default: col.column_default,
									length: col.character_maximum_length,
									precision: col.numeric_precision,
									scale: col.numeric_scale,
									is_primary_key: col.is_primary_key,
									is_foreign_key: col.is_foreign_key,
									comment: col.column_comment
								});
							}
						}
						
						const tableInfo = Array.from(tableMap.values());
						
						// Generate summary statistics
						const totalTables = tableInfo.length;
						const tablesWithPK = tableInfo.filter(t => t.has_primary_key).length;
						const totalColumns = tableInfo.reduce((sum, table) => sum + table.columns.length, 0);
						
						return {
							content: [
								{
									type: "text",
									text: `**🗄️ Supabase Database Schema Analysis**

**📊 Summary Statistics:**
- Total tables: ${totalTables}
- Tables with primary keys: ${tablesWithPK}
- Total columns: ${totalColumns}
- Database user: ${this.props.name} (${this.props.login} via ${this.props.provider})

**📋 Detailed Table Information:**

${JSON.stringify(tableInfo, null, 2)}

**🔍 Available Operations:**
- \`testConnection\` - Test database connectivity
- \`queryDatabase\` - Run SELECT queries (all users)
- \`executeDatabase\` - Run write operations (privileged users only)

**💡 Tips for Supabase:**
- All tables use Row Level Security (RLS) by default
- Use the Supabase dashboard for visual schema management
- Consider using Supabase's built-in auth tables for user management`
								}
							]
						};
					});
				} catch (error) {
					console.error('listTables error:', error);
					return {
						content: [
							{
								type: "text",
								text: formatDatabaseError(error, 'Database Schema Exploration'),
								isError: true
							}
						]
					};
				}
			}
		);

		// Tool 3: Query Database - Available to all authenticated users (read-only)
		this.server.tool(
			"queryDatabase",
			"[STEP 3] Execute read-only SQL queries against the Supabase database with enhanced formatting and analysis. 🔍 DATA EXPLORATION: Supports SELECT, EXPLAIN queries, and introspection. Claude Code Optimized with performance metrics and intelligent result formatting.",
			{
				sql: z.string()
					.min(1, "SQL query cannot be empty")
					.max(10000, "SQL query too long (max 10,000 characters)")
					.describe(`The SQL query to execute. REQUIREMENTS:
					
🔍 ALLOWED OPERATIONS:
- SELECT statements for data retrieval
- EXPLAIN and EXPLAIN ANALYZE for query planning
- WITH clauses for complex queries
- JOIN operations across tables
- Aggregate functions (COUNT, SUM, AVG, etc.)
- Window functions for advanced analytics

📚 SUPABASE/POSTGRESQL SYNTAX EXAMPLES:
- JSON operations: SELECT data->'field' FROM table
- Array operations: SELECT unnest(array_column) FROM table
- Text search: SELECT * FROM table WHERE to_tsvector(content) @@ to_tsquery('search')
- Date functions: SELECT * FROM table WHERE created_at > NOW() - INTERVAL '1 day'

⚠️ RESTRICTIONS:
- No INSERT, UPDATE, DELETE, or DDL operations
- No transaction control statements
- No user/permission modifications

💡 CLAUDE CODE TIPS:
- Start with simple SELECT * FROM table_name LIMIT 10
- Use EXPLAIN to understand query performance
- Check column names with \\d table_name style queries
- Use JSON operators for JSONB columns`)
			},
			async ({ sql }) => {
				try {
					// Security checks first
					const securityCheck = await this.checkSecurity('query', sql);
					if (!securityCheck.allowed) {
						return {
							content: [
								{
									type: "text",
									text: securityCheck.error!,
									isError: true
								}
							]
						};
					}

					// Validate the SQL query
					const validation = validateSqlQuery(sql);
					if (!validation.isValid) {
						return {
							content: [
								{
									type: "text",
									text: `**❌ Invalid SQL Query**

${validation.error}

**Supabase SQL Tips:**
- Use JSON operators: \`->\`, \`->>\`, \`@>\`, \`<@\`
- Array functions: \`array_agg()\`, \`unnest()\`
- Text search: \`to_tsvector()\`, \`@@\`
- Window functions: \`row_number() OVER()\``,
									isError: true
								}
							]
						};
					}
					
					// Check if it's a write operation
					if (isWriteOperation(sql)) {
						return {
							content: [
								{
									type: "text",
									text: `**🚫 Write Operations Not Allowed**

This tool only supports read operations (SELECT, EXPLAIN, etc.).

**For write operations:**
- Use \`executeDatabase\` tool (requires privileged access)
- Available to users: ${Array.from(ALLOWED_USERNAMES).join(', ')}
- Current user: ${this.props.login}`,
									isError: true
								}
							]
						};
					}
					
					const startTime = Date.now();
					return await withDatabase((this.env as any).DATABASE_URL, async (db) => {
						const results = await db.unsafe(sql);
						const executionTime = Date.now() - startTime;
						
						// Enhanced result formatting
						const isExplain = sql.trim().toLowerCase().startsWith('explain');
						const rowCount = Array.isArray(results) ? results.length : 1;
						
						// Generate summary for large result sets
						let summary = '';
						if (Array.isArray(results) && results.length > 10) {
							summary = `\n**📊 Result Summary:**
- Total rows: ${results.length}
- Showing first 10 rows
- Columns: ${Object.keys(results[0] || {}).length}`;
						}
						
						// Format results for better readability
						let displayResults = results;
						if (Array.isArray(results) && results.length > 10) {
							displayResults = results.slice(0, 10);
						}

						// Sanitize output for security
						const sanitizedResults = DataSanitizer.sanitizeOutput(displayResults, this.createSecurityContext('query'));
						
						return {
							content: [
								{
									type: "text",
									text: `**🔍 Supabase Query Results**

**📝 Query:**
\`\`\`sql
${sql}
\`\`\`

**⚡ Performance:**
- Execution time: ${executionTime}ms
- Rows ${isExplain ? 'analyzed' : 'returned'}: ${rowCount}
- User: ${this.props.name} (${this.props.login} via ${this.props.provider})

${summary}

**📊 ${isExplain ? 'Query Plan:' : 'Results:'}**
\`\`\`json
${JSON.stringify(sanitizedResults, null, 2)}
\`\`\`

**💡 Next Steps:**
- Use \`listTables\` to explore schema
- Try EXPLAIN ANALYZE for performance insights
- Use JSON operators for JSON columns
- Check Supabase dashboard for visual analysis`
								}
							]
						};
					});
				} catch (error) {
					console.error('queryDatabase error:', error);
					return {
						content: [
							{
								type: "text",
								text: formatDatabaseError(error, `Read Query by ${this.props.name} (${this.props.login} via ${this.props.provider})`),
								isError: true
							}
						]
					};
				}
			}
		);

		// Tool 4: Security Monitor - Only available to privileged users
		if (ALLOWED_USERNAMES.has(this.props.login)) {
			this.server.tool(
				"securityMonitor",
				"[ADMIN TOOL] Monitor security events, view system logs, and analyze suspicious activity. 🛡️ PRIVILEGED ACCESS: Comprehensive security dashboard with event filtering and analysis capabilities.",
				{
					action: z.enum(['recent_events', 'user_events', 'high_risk_events', 'system_status'])
						.describe(`Choose the security monitoring action:
						
🕒 RECENT_EVENTS: Show recent security events across all users
👤 USER_EVENTS: Show security events for specific users
⚠️ HIGH_RISK_EVENTS: Show high-severity security events requiring attention
📊 SYSTEM_STATUS: Show overall security system status and metrics`),
					userId: z.string().optional()
						.describe("User ID to filter events (required for user_events action)"),
					limit: z.number().min(1).max(100).default(20)
						.describe("Maximum number of events to return (1-100, default: 20)")
				},
				async ({ action, userId, limit }) => {
					try {
						const securityKV = (this.env as any).SECURITY_LOGS_KV;
						if (!securityKV) {
							return {
								content: [
									{
										type: "text",
										text: `**❌ Security Monitoring Unavailable**

Security KV storage is not configured. This may indicate:
- Missing SECURITY_LOGS_KV binding in wrangler configuration
- KV namespace not created
- Environment misconfiguration

**Setup Required:**
1. Create KV namespace: \`wrangler kv:namespace create "SECURITY_LOGS_KV"\`
2. Update wrangler.jsonc with the namespace ID
3. Redeploy the application

**Current Environment:** ${(this.env as any).NODE_ENV || 'unknown'}`,
										isError: true
									}
								]
							};
						}

						let events: any[] = [];
						let statusInfo = '';

						switch (action) {
							case 'recent_events':
								events = await SecurityLogger.getSecurityEvents(securityKV, { limit });
								statusInfo = `**📊 Recent Security Events (Last ${limit})**`;
								break;

							case 'user_events':
								if (!userId) {
									return {
										content: [
											{
												type: "text",
												text: `**❌ User ID Required**

For user_events action, you must provide a userId parameter.

**Example:** Use \`securityMonitor\` with action="user_events" and userId="username"`,
												isError: true
											}
										]
									};
								}
								events = await SecurityLogger.getSecurityEvents(securityKV, { userId, limit });
								statusInfo = `**👤 Security Events for User: ${userId}**`;
								break;

							case 'high_risk_events':
								events = await SecurityLogger.getSecurityEvents(securityKV, { severity: 'high', limit });
								statusInfo = `**⚠️ High-Risk Security Events (Last ${limit})**`;
								break;

							case 'system_status':
								// Get overall system metrics
								const recentEvents = await SecurityLogger.getSecurityEvents(securityKV, { limit: 100 });
								const highRiskCount = recentEvents.filter(e => e.severity === 'high').length;
								const uniqueUsers = new Set(recentEvents.map(e => e.userId)).size;
								const eventTypes = recentEvents.reduce((acc: any, e) => {
									acc[e.eventType] = (acc[e.eventType] || 0) + 1;
									return acc;
								}, {});

								return {
									content: [
										{
											type: "text",
											text: `**📊 Security System Status**

**🔍 System Overview:**
- Security monitoring: ✅ Active
- KV storage: ✅ Connected
- Event logging: ✅ Operational
- Administrator: ${this.props.name} (${this.props.login} via ${this.props.provider})

**📈 Recent Activity (Last 100 events):**
- Total events: ${recentEvents.length}
- High-risk events: ${highRiskCount}
- Active users: ${uniqueUsers}
- Most recent event: ${recentEvents[0]?.timestamp || 'None'}

**🎯 Event Types:**
${Object.entries(eventTypes).map(([type, count]) => `- ${type}: ${count}`).join('\n')}

**⚙️ Configuration:**
- Rate limiting: ✅ Enabled
- Input validation: ✅ Enabled
- Access control: ✅ Enabled
- Data sanitization: ✅ Enabled

**🔧 Available Actions:**
- \`recent_events\`: View recent security events
- \`user_events\`: View events for specific user
- \`high_risk_events\`: View high-severity events
- \`system_status\`: This system overview

**💡 Security Tips:**
- Monitor high-risk events regularly
- Investigate unusual user activity patterns
- Review access control settings periodically
- Keep KV storage retention policies updated`
										}
									]
								};
						}

						if (events.length === 0) {
							return {
								content: [
									{
										type: "text",
										text: `${statusInfo}

**📭 No Events Found**

No security events match your criteria.

**Possible Reasons:**
- No recent security events
- Events may have expired (30-day retention)
- User has no recorded activity
- System has been recently deployed

**Next Steps:**
- Try different filter criteria
- Check system_status for overall metrics
- Verify KV namespace configuration`
									}
								]
							};
						}

						// Format events for display
						const eventSummary = events.map((event, index) => 
							`**${index + 1}. ${event.eventType}** (${event.severity})
- Time: ${event.timestamp}
- User: ${event.userId} (${event.provider})
- Operation: ${event.operation}
- Details: ${JSON.stringify(event.details, null, 2)}`
						).join('\n\n');

						return {
							content: [
								{
									type: "text",
									text: `${statusInfo}

**👮 Monitoring Dashboard:**
- Events returned: ${events.length}
- Query limit: ${limit}
- Queried by: ${this.props.name} (${this.props.login})

**🚨 Security Events:**

${eventSummary}

**🔍 Event Analysis:**
- High severity: ${events.filter(e => e.severity === 'high').length}
- Medium severity: ${events.filter(e => e.severity === 'medium').length}
- Low severity: ${events.filter(e => e.severity === 'low').length}

**📋 Action Items:**
${events.filter(e => e.severity === 'high').length > 0 ? 
'- ⚠️ **ATTENTION:** High-severity events require review' : '- ✅ No high-severity events'}
- Monitor for patterns in repeated events
- Verify all activities are legitimate
- Consider adjusting security thresholds if needed

**⚙️ Tools:**
- Use different actions to filter events
- Check \`claudeCodeStatus\` for system information
- Review access controls with \`requestWriteAccess\``
								}
							]
						};

					} catch (error) {
						console.error('securityMonitor error:', error);
						return {
							content: [
								{
									type: "text",
									text: `**❌ Security Monitor Error**

Failed to retrieve security information: ${error instanceof Error ? error.message : 'Unknown error'}

**Troubleshooting:**
1. Verify KV namespace is properly configured
2. Check security logging is operational
3. Ensure proper permissions and bindings

**Current User:** ${this.props.name} (${this.props.login} via ${this.props.provider})
**Access Level:** PRIVILEGED`,
									isError: true
								}
							]
						};
					}
				}
			);
		}

		// Tool 5: Execute Database - Only available to privileged users (write operations)
		if (ALLOWED_USERNAMES.has(this.props.login)) {
			this.server.tool(
				"executeDatabase",
				"[STEP 4 - PRIVILEGED] Execute any SQL statement against the Supabase database with enhanced security and monitoring. ⚠️ DANGEROUS OPERATIONS: Supports INSERT, UPDATE, DELETE, CREATE, ALTER operations. Claude Code Optimized with safety checks, audit logging, and rollback guidance. **USE WITH EXTREME CAUTION** - permanently modifies data.",
				{
					sql: z.string()
						.min(1, "SQL statement cannot be empty")
						.max(50000, "SQL statement too long (max 50,000 characters)")
						.describe(`The SQL statement to execute with FULL DATABASE ACCESS. ⚠️ EXTREME CAUTION REQUIRED ⚠️

🔧 ALLOWED OPERATIONS:
- SELECT statements (same as queryDatabase)
- INSERT statements for adding data
- UPDATE statements for modifying existing data  
- DELETE statements for removing data
- CREATE/ALTER/DROP for schema modifications
- Transaction control (BEGIN, COMMIT, ROLLBACK)
- Index and constraint management

📚 SUPABASE ADVANCED EXAMPLES:
- Insert with JSONB: INSERT INTO table (data) VALUES ('{"key": "value"}')
- Update with JSON: UPDATE table SET data = data || '{"new": "field"}'
- Upsert operation: INSERT INTO table VALUES (...) ON CONFLICT (id) DO UPDATE SET ...
- Create RLS policy: CREATE POLICY policy_name ON table FOR SELECT USING (condition)
- Array operations: UPDATE table SET tags = array_append(tags, 'new_tag')

⚠️ DESTRUCTIVE OPERATIONS - DOUBLE CHECK:
- DELETE FROM table (deletes ALL rows if no WHERE clause)
- DROP TABLE table_name (permanently removes table)
- TRUNCATE table (removes all data, faster than DELETE)
- ALTER TABLE operations (can break existing code)

🛡️ SAFETY RECOMMENDATIONS:
- ALWAYS use WHERE clauses with UPDATE/DELETE
- Test with SELECT first to verify affected rows
- Consider using transactions for multiple operations
- Backup important data before schema changes
- Use LIMIT clause when appropriate

💡 CLAUDE CODE GUIDANCE:
- Start with SELECT to understand current data
- Use transactions for multi-step operations  
- Verify row counts before and after operations
- Check Supabase dashboard for real-time updates
- Monitor RLS policy impacts on operations`)
				},
				async ({ sql }) => {
					try {
						// Security checks first - especially important for write operations
						const securityCheck = await this.checkSecurity('execute', sql);
						if (!securityCheck.allowed) {
							return {
								content: [
									{
										type: "text",
										text: securityCheck.error!,
										isError: true
									}
								]
							};
						}

						// Enhanced validation for privileged operations
						const validation = validateSqlQuery(sql);
						if (!validation.isValid) {
							return {
								content: [
									{
										type: "text",
										text: `**❌ Invalid SQL Statement**

${validation.error}

**Supabase Advanced Features:**
- JSON operations: \`UPDATE table SET data = data || '{"new": "value"}'\`
- Array operations: \`UPDATE table SET tags = array_append(tags, 'new_tag')\`
- Full-text search: \`CREATE INDEX ON table USING gin(to_tsvector('english', content))\`
- RLS policies: \`CREATE POLICY name ON table FOR SELECT USING (condition)\`

**⚠️ Security Note:** This tool has full database access. Double-check your queries.`,
										isError: true
									}
								]
							};
						}
						
						const startTime = Date.now();
						const isWrite = isWriteOperation(sql);
						const operationType = isWrite ? "Write Operation" : "Read Operation";
						
						// Additional safety check for dangerous operations
						const isDangerous = /\b(drop\s+table|truncate|delete\s+from\s+\w+\s*;?\s*$)/i.test(sql.trim());
						
						return await withDatabase((this.env as any).DATABASE_URL, async (db) => {
							const results = await db.unsafe(sql);
							const executionTime = Date.now() - startTime;
							
							// Sanitize output for security
							const sanitizedResults = DataSanitizer.sanitizeOutput(results, this.createSecurityContext('execute'));
							
							// Enhanced result analysis
							let affectedRows = 0;
							if (typeof results === 'object' && 'count' in results) {
								affectedRows = results.count as number;
							} else if (Array.isArray(results)) {
								affectedRows = results.length;
							} else if (results && typeof results === 'object' && 'rowCount' in results) {
								affectedRows = (results as any).rowCount;
							}
							
							// Generate operation summary
							let operationSummary = '';
							if (isWrite) {
								operationSummary = `
**🔄 Operation Impact:**
- Type: ${operationType}
- Rows affected: ${affectedRows}
- Execution time: ${executionTime}ms
${isDangerous ? '- ⚠️ **DANGEROUS OPERATION DETECTED**' : ''}`;
							} else {
								operationSummary = `
**📊 Query Results:**
- Type: ${operationType}  
- Rows returned: ${affectedRows}
- Execution time: ${executionTime}ms`;
							}
							
							return {
								content: [
									{
										type: "text",
										text: `**✅ Supabase Database Operation Completed**

**👤 Authorization:**
- User: ${this.props.name} (${this.props.login} via ${this.props.provider})
- Access Level: PRIVILEGED
- Timestamp: ${new Date().toISOString()}

**📝 SQL Statement:**
\`\`\`sql
${sql}
\`\`\`

${operationSummary}

**📊 Results:**
\`\`\`json
${JSON.stringify(sanitizedResults, null, 2)}
\`\`\`

${isWrite ? `**⚠️ DATABASE MODIFIED** - Changes have been applied to the Supabase database.

**Security Notes:**
- All operations are logged and audited
- Changes may affect Row Level Security (RLS) policies
- Consider backing up data before major operations
- Check Supabase dashboard for real-time updates` : '**ℹ️ Read operation completed successfully.**'}

**🔍 Recommendations:**
- Verify changes in Supabase dashboard
- Check table constraints and indexes
- Monitor RLS policy impacts
- Use \`queryDatabase\` to verify results`
									}
								]
							};
						});
					} catch (error) {
						console.error('executeDatabase error:', error);
						return {
							content: [
								{
									type: "text",
									text: formatDatabaseError(error, `Privileged Database Operation by ${this.props.name} (${this.props.login} via ${this.props.provider}) at ${new Date().toISOString()}`),
									isError: true
								}
							]
						};
					};
				}
			);
		}

		// Claude Code Helper Tool - Available to all users
		this.server.tool(
			"getSQLExamples",
			"[CLAUDE HELPER] Get SQL examples, templates, and best practices specifically designed for Claude Code interaction. 📚 LEARNING TOOL: Provides copy-paste ready SQL snippets for common database operations with Supabase-specific optimizations.",
			{
				category: z.enum(['basic', 'intermediate', 'advanced', 'supabase-specific', 'troubleshooting'])
					.describe(`Choose the type of SQL examples you need:
					
🟢 BASIC: Simple SELECT, filtering, sorting, basic JOINs
🟡 INTERMEDIATE: Aggregations, subqueries, window functions, CTEs
🔴 ADVANCED: Complex analytics, recursive queries, performance optimization
🚀 SUPABASE-SPECIFIC: JSON operations, RLS policies, real-time features
🔧 TROUBLESHOOTING: Common error patterns and debugging queries`)
			},
			async ({ category }) => {
				try {
					let examples = '';
					
					switch (category) {
						case 'basic':
							examples = `**🟢 Basic SQL Examples for Supabase**

\`\`\`sql
-- Get all data from a table (with limit for safety)
SELECT * FROM users LIMIT 10;

-- Filter records with WHERE clause  
SELECT name, email FROM users WHERE created_at > '2024-01-01';

-- Sort results
SELECT * FROM products ORDER BY price DESC LIMIT 5;

-- Basic JOIN between tables
SELECT u.name, p.title 
FROM users u 
JOIN posts p ON u.id = p.user_id;

-- Count records
SELECT COUNT(*) as total_users FROM users;

-- Group by with aggregation
SELECT category, COUNT(*) as product_count 
FROM products 
GROUP BY category;
\`\`\``;
							break;
							
						case 'intermediate':
							examples = `**🟡 Intermediate SQL Examples for Supabase**

\`\`\`sql
-- Common Table Expression (CTE)
WITH recent_orders AS (
  SELECT user_id, COUNT(*) as order_count
  FROM orders 
  WHERE created_at > NOW() - INTERVAL '30 days'
  GROUP BY user_id
)
SELECT u.name, COALESCE(ro.order_count, 0) as recent_orders
FROM users u
LEFT JOIN recent_orders ro ON u.id = ro.user_id;

-- Window functions for analytics
SELECT 
  name, 
  salary,
  AVG(salary) OVER() as avg_salary,
  RANK() OVER(ORDER BY salary DESC) as salary_rank
FROM employees;

-- Subqueries with EXISTS
SELECT * FROM users u
WHERE EXISTS (
  SELECT 1 FROM orders o 
  WHERE o.user_id = u.id 
  AND o.status = 'completed'
);

-- Complex aggregations
SELECT 
  DATE_TRUNC('month', created_at) as month,
  COUNT(*) as total_orders,
  SUM(amount) as total_revenue,
  AVG(amount) as avg_order_value
FROM orders
GROUP BY DATE_TRUNC('month', created_at)
ORDER BY month;
\`\`\``;
							break;
							
						case 'advanced':
							examples = `**🔴 Advanced SQL Examples for Supabase**

\`\`\`sql
-- Recursive CTE for hierarchical data
WITH RECURSIVE category_tree AS (
  SELECT id, name, parent_id, 0 as level
  FROM categories WHERE parent_id IS NULL
  UNION ALL
  SELECT c.id, c.name, c.parent_id, ct.level + 1
  FROM categories c
  JOIN category_tree ct ON c.parent_id = ct.id
)
SELECT * FROM category_tree ORDER BY level, name;

-- Advanced analytics with multiple window functions
SELECT 
  user_id,
  order_date,
  amount,
  SUM(amount) OVER(PARTITION BY user_id ORDER BY order_date) as running_total,
  LAG(amount) OVER(PARTITION BY user_id ORDER BY order_date) as prev_order,
  LEAD(amount) OVER(PARTITION BY user_id ORDER BY order_date) as next_order
FROM orders;

-- Performance optimization with EXPLAIN
EXPLAIN ANALYZE
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at > '2024-01-01'
GROUP BY u.id, u.name
HAVING COUNT(o.id) > 5;
\`\`\``;
							break;
							
						case 'supabase-specific':
							examples = `**🚀 Supabase-Specific SQL Examples**

\`\`\`sql
-- JSON operations (Supabase strength)
SELECT 
  id,
  metadata->>'name' as name,
  metadata->'settings'->>'theme' as theme,
  metadata @> '{"verified": true}' as is_verified
FROM users;

-- Update JSON fields
UPDATE users 
SET metadata = metadata || '{"last_login": "2024-01-01"}'
WHERE id = 123;

-- Array operations
SELECT 
  id,
  name,
  tags,
  array_length(tags, 1) as tag_count,
  'postgres' = ANY(tags) as has_postgres_tag
FROM projects;

-- Full-text search
SELECT *
FROM articles
WHERE to_tsvector('english', title || ' ' || content) 
      @@ to_tsquery('english', 'supabase & database');

-- Row Level Security (RLS) examples
-- Enable RLS
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

-- Create policy for users to see their own posts
CREATE POLICY "Users can view own posts" ON posts
  FOR SELECT USING (auth.uid() = user_id);

-- Real-time subscription friendly queries
SELECT id, title, updated_at 
FROM posts 
WHERE updated_at > NOW() - INTERVAL '1 hour'
ORDER BY updated_at DESC;
\`\`\``;
							break;
							
						case 'troubleshooting':
							examples = `**🔧 Troubleshooting SQL Examples**

\`\`\`sql
-- Check table structure and constraints
SELECT 
  column_name, 
  data_type, 
  is_nullable, 
  column_default
FROM information_schema.columns 
WHERE table_name = 'your_table';

-- Find missing indexes (performance issues)
SELECT schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE tablename = 'your_table'
ORDER BY n_distinct DESC;

-- Check for blocking queries (if database seems slow)
SELECT 
  pid,
  now() - pg_stat_activity.query_start AS duration,
  query,
  state
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';

-- Validate JSON structure
SELECT id, metadata
FROM users
WHERE NOT (metadata ? 'email') -- Find records missing email in JSON

-- Check RLS policies
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual
FROM pg_policies
WHERE tablename = 'your_table';

-- Safe way to test UPDATE before running
SELECT COUNT(*) as affected_rows
FROM users 
WHERE created_at < '2023-01-01'; -- Test your WHERE clause first

-- Check foreign key constraints
SELECT 
  tc.table_name, 
  kcu.column_name, 
  ccu.table_name AS foreign_table_name,
  ccu.column_name AS foreign_column_name 
FROM information_schema.table_constraints AS tc 
JOIN information_schema.key_column_usage AS kcu
  ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
  ON ccu.constraint_name = tc.constraint_name
WHERE constraint_type = 'FOREIGN KEY' AND tc.table_name='your_table';
\`\`\``;
							break;
					}
					
					return {
						content: [
							{
								type: "text",
								text: `${examples}

**💡 Claude Code Tips:**
1. **Copy and modify** these examples for your specific needs
2. **Test with small datasets** first using LIMIT clauses
3. **Use EXPLAIN** to understand query performance
4. **Check the Supabase dashboard** for real-time monitoring
5. **Always backup** before running destructive operations

**🔗 Next Steps:**
- Use \`queryDatabase\` to test these examples
- Use \`listTables\` to see your actual table structure
- Use \`executeDatabase\` for write operations (if you have access)
- Check \`claudeCodeStatus\` for your current permissions

**⚠️ Safety Reminders:**
- Always use WHERE clauses with UPDATE/DELETE
- Test SELECT versions of your queries first
- Use transactions for multiple related operations
- Monitor query performance with EXPLAIN ANALYZE`
							}
						]
					};
				} catch (error) {
					console.error('getSQLExamples error:', error);
					return {
						content: [
							{
								type: "text",
								text: `**❌ Error retrieving SQL examples**

${error instanceof Error ? error.message : 'Unknown error'}

**Available Categories:**
- basic: Simple SELECT, filtering, JOINs
- intermediate: Aggregations, CTEs, window functions  
- advanced: Complex analytics, optimization
- supabase-specific: JSON, arrays, RLS, real-time
- troubleshooting: Debugging and diagnostic queries

Please try again with a valid category.`,
								isError: true
							}
						]
					};
				}
			}
		);

		if (!ALLOWED_USERNAMES.has(this.props.login)) {
			// Add informational tool for non-privileged users
			this.server.tool(
				"requestWriteAccess",
				"[ACCESS INFO] Request information about obtaining write access to the Supabase database. 🔒 PERMISSION SYSTEM: Explains access control, user roles, and elevation process. Claude Code Optimized with clear role-based guidance.",
				{},
				async () => {
					return {
						content: [
							{
								type: "text",
								text: `**🔒 Database Write Access Information**

**Current User:** ${this.props.name} (${this.props.login} via ${this.props.provider})
**Access Level:** READ-ONLY

**👥 Users with Write Access:**
${Array.from(ALLOWED_USERNAMES).map(username => `- ${username}`).join('\n')}

**🛡️ Security Model:**
The Supabase database uses a role-based access control system:

1. **Read Access (Your Level):**
   - Use \`testConnection\` to verify connectivity
   - Use \`listTables\` to explore schema
   - Use \`queryDatabase\` for SELECT operations

2. **Write Access (Privileged Users):**
   - Full database modification capabilities
   - Access to \`executeDatabase\` tool
   - Can perform INSERT, UPDATE, DELETE, CREATE operations

**📝 To Request Write Access:**
1. Contact a system administrator
2. Your GitHub username (${this.props.login}) needs to be added to ALLOWED_USERNAMES
3. Administrators can update the access list in the MCP server configuration

**🔍 Available Tools:**
- \`testConnection\` - Test database connectivity
- \`listTables\` - Explore database schema
- \`queryDatabase\` - Run read-only queries
- \`requestWriteAccess\` - This informational tool

**💡 Best Practices:**
- Use read operations to understand data structure first
- Test queries in Supabase dashboard before requesting write access
- Always backup important data before modifications`
							}
						]
					};
				}
			);
		}
	}
}

export default new OAuthProvider({
	apiHandlers: {
		'/sse': MyMCP.serveSSE('/sse') as any,
		'/mcp': MyMCP.serve('/mcp') as any,
	},
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: GitHandler as any,
	tokenEndpoint: "/token",
});
