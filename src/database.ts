import postgres from "postgres";

let dbInstance: postgres.Sql | null = null;

/**
 * Get database connection singleton
 * Optimized for Supabase PostgreSQL with Cloudflare Workers
 */
export function getDb(databaseUrl: string): postgres.Sql {
	if (!dbInstance) {
		dbInstance = postgres(databaseUrl, {
			// Connection pool settings optimized for Supabase + Cloudflare Workers
			max: 3, // Conservative connection limit for Supabase
			idle_timeout: 20, 
			connect_timeout: 10,
			// Enable prepared statements for better performance
			prepare: true,
			// Supabase optimizations
			ssl: 'require', // Supabase requires SSL
			transform: {
				undefined: null, // Handle undefined values properly
			},
			// Connection string parsing for Supabase format
			host_type: 'tcp',
			// Keepalive settings for better connection stability
			keepalive: true,
		});
	}
	return dbInstance;
}

/**
 * Close database connection pool
 * Call this when the Durable Object is shutting down
 */
export async function closeDb(): Promise<void> {
	if (dbInstance) {
		try {
			await dbInstance.end();
		} catch (error) {
			console.error('Error closing database connection:', error);
		} finally {
			dbInstance = null;
		}
	}
}

/**
 * Execute a database operation with proper connection management
 * Optimized for Supabase PostgreSQL with enhanced error handling
 * 
 * Supabase connection string format:
 * postgresql://postgres:[password]@db.[project-ref].supabase.co:5432/postgres
 */
export async function withDatabase<T>(
	databaseUrl: string,
	operation: (db: postgres.Sql) => Promise<T>
): Promise<T> {
	const db = getDb(databaseUrl);
	const startTime = Date.now();
	try {
		const result = await operation(db);
		const duration = Date.now() - startTime;
		console.log(`Database operation completed successfully in ${duration}ms`);
		return result;
	} catch (error) {
		const duration = Date.now() - startTime;
		console.error(`Database operation failed after ${duration}ms:`, error);
		// Re-throw the error so it can be caught by Sentry in the calling code
		throw error;
	}
	// Note: With PostgreSQL connection pooling, we don't close individual connections
	// They're returned to the pool automatically. The pool is closed when the Durable Object shuts down.
}

/**
 * SQL injection protection: Basic SQL keyword validation
 * This is a simple check - in production you should use parameterized queries
 */
export function validateSqlQuery(sql: string): { isValid: boolean; error?: string } {
	const trimmedSql = sql.trim().toLowerCase();
	
	// Check for empty queries
	if (!trimmedSql) {
		return { isValid: false, error: "SQL query cannot be empty" };
	}
	
	// Check for obviously dangerous patterns
	const dangerousPatterns = [
		/;\s*drop\s+/i,
		/;\s*delete\s+.*\s+where\s+1\s*=\s*1/i,
		/;\s*update\s+.*\s+set\s+.*\s+where\s+1\s*=\s*1/i,
		/;\s*truncate\s+/i,
		/;\s*alter\s+/i,
		/;\s*create\s+/i,
		/;\s*grant\s+/i,
		/;\s*revoke\s+/i,
		/xp_cmdshell/i,
		/sp_executesql/i,
	];
	
	for (const pattern of dangerousPatterns) {
		if (pattern.test(sql)) {
			return { isValid: false, error: "Query contains potentially dangerous SQL patterns" };
		}
	}
	
	return { isValid: true };
}

/**
 * Check if a SQL query is a write operation
 */
export function isWriteOperation(sql: string): boolean {
	const trimmedSql = sql.trim().toLowerCase();
	const writeKeywords = [
		'insert', 'update', 'delete', 'create', 'drop', 'alter', 
		'truncate', 'grant', 'revoke', 'commit', 'rollback'
	];
	
	return writeKeywords.some(keyword => trimmedSql.startsWith(keyword));
}

/**
 * Enhanced error formatting for Claude Code interface
 * Provides detailed, actionable error messages with troubleshooting guidance
 */
export function formatDatabaseError(error: unknown, context?: string): string {
	if (error instanceof Error) {
		const errorMessage = error.message.toLowerCase();
		
		// Authentication errors
		if (errorMessage.includes('password') || errorMessage.includes('authentication')) {
			return `**🔐 Database Authentication Failed**

The database rejected your credentials. This could mean:
- Your DATABASE_URL has an incorrect password
- Your Supabase project credentials have changed
- The database user account has been disabled

**Troubleshooting Steps:**
1. Check your DATABASE_URL in environment variables
2. Verify your Supabase project is active in the dashboard
3. Reset your database password in Supabase settings
4. Ensure you're using the correct project reference in the URL

**Format:** \`postgresql://postgres:[password]@db.[project-ref].supabase.co:5432/postgres\``;
		}
		
		// Connection timeout errors
		if (errorMessage.includes('timeout') || errorMessage.includes('timed out')) {
			return `**⏱️ Database Connection Timeout**

The database connection took too long to establish or complete.

**Common Causes:**
- Network connectivity issues
- Supabase project is paused or inactive
- High database load or maintenance
- Cloudflare Workers connection limits reached

**Troubleshooting Steps:**
1. Check Supabase project status in dashboard
2. Verify your internet connection
3. Try the operation again in a few minutes
4. Check Supabase status page for service issues
5. Consider reducing query complexity`;
		}
		
		// General connection errors
		if (errorMessage.includes('connection') || errorMessage.includes('connect')) {
			return `**🌐 Database Connection Failed**

Unable to establish a connection to your Supabase database.

**Possible Issues:**
- Incorrect DATABASE_URL format
- Supabase project doesn't exist or is deleted
- Network/firewall blocking the connection
- SSL certificate issues

**Troubleshooting Steps:**
1. Verify DATABASE_URL format is correct
2. Check if project exists in Supabase dashboard
3. Ensure SSL is enabled (Supabase requires it)
4. Test connection from Supabase SQL editor
5. Check if project is in correct region`;
		}
		
		// SQL syntax errors
		if (errorMessage.includes('syntax error') || errorMessage.includes('invalid syntax')) {
			return `**📝 SQL Syntax Error**

Your SQL query contains a syntax error.

**Error Details:** ${error.message}

**Common Syntax Issues:**
- Missing quotes around string values
- Incorrect table or column names
- Invalid SQL keywords or structure
- Missing semicolons or commas

**Debugging Tips:**
1. Check table and column names with \`listTables\`
2. Use SQL examples from \`getSQLExamples\`
3. Test simpler versions of your query first
4. Validate query in Supabase SQL editor`;
		}
		
		// Permission/RLS errors
		if (errorMessage.includes('permission') || errorMessage.includes('policy') || errorMessage.includes('rls')) {
			return `**🛡️ Database Permission Error**

Row Level Security (RLS) policy or permission restriction.

**Error Details:** ${error.message}

**Supabase RLS Information:**
- Tables may have Row Level Security policies enabled
- Policies control which rows users can access
- Some operations require specific user permissions

**Troubleshooting Steps:**
1. Check RLS policies in Supabase dashboard
2. Verify your authentication level and user role
3. Check if table requires specific user context
4. Consider disabling RLS for testing (carefully)
5. Review Supabase Auth documentation`;
		}
		
		// Constraint violation errors
		if (errorMessage.includes('constraint') || errorMessage.includes('foreign key') || errorMessage.includes('unique')) {
			return `**⚠️ Database Constraint Violation**

A database constraint prevented your operation.

**Error Details:** ${error.message}

**Common Constraint Types:**
- **Unique**: Duplicate value in unique column
- **Foreign Key**: Referenced record doesn't exist
- **Not Null**: Required field is empty
- **Check**: Custom validation rule failed

**Resolution Steps:**
1. Check existing data with SELECT queries
2. Verify foreign key references exist
3. Ensure required fields have values
4. Review table constraints with \`listTables\``;
		}
		
		// Type conversion errors
		if (errorMessage.includes('invalid input') || errorMessage.includes('type') || errorMessage.includes('cast')) {
			return `**🔄 Data Type Error**

Data type mismatch or invalid value format.

**Error Details:** ${error.message}

**Common Type Issues:**
- String values in numeric columns
- Invalid date/time formats
- JSON syntax errors in JSONB columns
- Array format problems

**Solutions:**
1. Check column data types with \`listTables\`
2. Validate data formats before insertion
3. Use proper type casting (::text, ::integer, etc.)
4. Verify JSON syntax for JSONB columns`;
		}
		
		// Generic error with context
		const contextInfo = context ? `\n\n**Operation Context:** ${context}` : '';
		return `**❌ Database Error**

${error.message}${contextInfo}

**General Troubleshooting:**
1. Try \`testConnection\` to verify database connectivity
2. Use \`listTables\` to understand your schema
3. Test with simpler queries first
4. Check Supabase logs in the dashboard
5. Contact support if the issue persists

**Need Help?**
- Use \`getSQLExamples\` for query templates
- Check \`claudeCodeStatus\` for system information
- Review Supabase documentation for advanced features`;
	}
	
	// Unknown error type
	const contextInfo = context ? ` (Context: ${context})` : '';
	return `**❓ Unknown Database Error**

An unexpected error occurred${contextInfo}.

**Immediate Actions:**
1. Try the operation again
2. Use \`testConnection\` to verify system status
3. Check \`claudeCodeStatus\` for any known issues
4. Contact support with error details if problem persists

**Error Type:** ${typeof error}
**Error Value:** ${String(error)}`;
}