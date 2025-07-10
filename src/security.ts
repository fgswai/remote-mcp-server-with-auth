/**
 * MCP Security Implementation
 * Based on MCP Security Checklist recommendations
 */

import { z } from "zod";

// Rate limiting configuration
export interface RateLimitConfig {
	windowMs: number; // Time window in milliseconds
	maxRequests: number; // Maximum requests per window
	skipSuccessfulRequests?: boolean;
}

// Security context for operations
export interface SecurityContext {
	userId: string;
	provider: string;
	userAgent?: string;
	ipAddress?: string;
	timestamp: number;
	operation: string;
}

// Rate limiting storage (in-memory for Workers)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

/**
 * Enhanced input validation with security measures
 */
export class SecurityValidator {
	
	/**
	 * Validate SQL query with enhanced security checks
	 */
	static validateSQLInput(sql: string, context: SecurityContext): { isValid: boolean; error?: string; risk: 'low' | 'medium' | 'high' } {
		// Basic validation
		if (!sql || typeof sql !== 'string') {
			return { isValid: false, error: 'SQL input must be a non-empty string', risk: 'medium' };
		}

		// Length validation
		if (sql.length > 100000) {
			SecurityLogger.logSecurityEvent('OVERSIZED_SQL_QUERY', context, { queryLength: sql.length });
			return { isValid: false, error: 'SQL query exceeds maximum allowed length (100,000 characters)', risk: 'high' };
		}

		// Dangerous pattern detection
		const dangerousPatterns = [
			// SQL injection patterns
			/(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*?;\s*\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
			// Comment injection
			/(\/\*[\s\S]*?\*\/|--[^\r\n]*)/g,
			// Stacked queries (multiple statements)
			/;\s*(select|insert|update|delete|drop|create|alter|exec|execute)\b/i,
			// System function calls
			/\b(xp_|sp_|fn_|sys\.|information_schema\.)/i,
			// Timing attacks
			/\b(waitfor|delay|sleep|benchmark)\b/i,
			// File system access
			/\b(load_file|into\s+outfile|into\s+dumpfile)\b/i,
		];

		for (const pattern of dangerousPatterns) {
			if (pattern.test(sql)) {
				SecurityLogger.logSecurityEvent('DANGEROUS_SQL_PATTERN', context, { pattern: pattern.source });
				return { isValid: false, error: 'SQL query contains potentially dangerous patterns', risk: 'high' };
			}
		}

		// Advanced SQL injection detection
		const sqlInjectionPatterns = [
			// Boolean-based blind SQL injection
			/(\bor\b|\band\b)\s+\d+\s*=\s*\d+/i,
			// Time-based blind SQL injection
			/\b(if|case|when)\s*\(/i,
			// Union-based SQL injection
			/\bunion\b.*\bselect\b/i,
			// Error-based SQL injection
			/\b(extractvalue|updatexml|exp)\s*\(/i,
		];

		let riskLevel: 'low' | 'medium' | 'high' = 'low';
		for (const pattern of sqlInjectionPatterns) {
			if (pattern.test(sql)) {
				riskLevel = 'medium';
				SecurityLogger.logSecurityEvent('POTENTIAL_SQL_INJECTION', context, { pattern: pattern.source });
				break;
			}
		}

		return { isValid: true, risk: riskLevel };
	}

	/**
	 * Validate user input for potential malicious content
	 */
	static validateUserInput(input: string, maxLength: number = 1000): { isValid: boolean; error?: string } {
		if (!input || typeof input !== 'string') {
			return { isValid: false, error: 'Input must be a non-empty string' };
		}

		if (input.length > maxLength) {
			return { isValid: false, error: `Input exceeds maximum length of ${maxLength} characters` };
		}

		// Check for potential XSS patterns
		const xssPatterns = [
			/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
			/javascript:/i,
			/on\w+\s*=/i,
			/<iframe\b[^>]*>/i,
		];

		for (const pattern of xssPatterns) {
			if (pattern.test(input)) {
				return { isValid: false, error: 'Input contains potentially malicious content' };
			}
		}

		return { isValid: true };
	}
}

/**
 * Rate limiting implementation
 */
export class RateLimiter {
	
	/**
	 * Check if request is within rate limits
	 */
	static checkRateLimit(identifier: string, config: RateLimitConfig, context: SecurityContext): { allowed: boolean; remaining: number; resetTime: number } {
		const key = `rate_limit:${identifier}`;
		const now = Date.now();
		
		// Clean up expired entries
		this.cleanupExpiredEntries(now);
		
		const current = rateLimitStore.get(key);
		
		if (!current || now > current.resetTime) {
			// First request or window expired
			const resetTime = now + config.windowMs;
			rateLimitStore.set(key, { count: 1, resetTime });
			
			return {
				allowed: true,
				remaining: config.maxRequests - 1,
				resetTime
			};
		}
		
		if (current.count >= config.maxRequests) {
			SecurityLogger.logSecurityEvent('RATE_LIMIT_EXCEEDED', context, { 
				identifier, 
				count: current.count, 
				limit: config.maxRequests 
			});
			
			return {
				allowed: false,
				remaining: 0,
				resetTime: current.resetTime
			};
		}
		
		current.count++;
		rateLimitStore.set(key, current);
		
		return {
			allowed: true,
			remaining: config.maxRequests - current.count,
			resetTime: current.resetTime
		};
	}
	
	/**
	 * Clean up expired rate limit entries
	 */
	private static cleanupExpiredEntries(now: number): void {
		for (const [key, value] of rateLimitStore.entries()) {
			if (now > value.resetTime) {
				rateLimitStore.delete(key);
			}
		}
	}
}

/**
 * Access control implementation
 */
export class AccessControl {
	
	/**
	 * Check if user has permission for operation
	 */
	static hasPermission(context: SecurityContext, operation: string, allowedUsers?: Set<string>): boolean {
		// Log access attempt
		SecurityLogger.logSecurityEvent('ACCESS_ATTEMPT', context, { operation });
		
		// Check for basic authentication
		if (!context.userId) {
			SecurityLogger.logSecurityEvent('UNAUTHORIZED_ACCESS', context, { operation });
			return false;
		}
		
		// Check operation-specific permissions
		switch (operation) {
			case 'read':
				return true; // All authenticated users can read
				
			case 'write':
			case 'execute':
			case 'admin':
				if (!allowedUsers?.has(context.userId)) {
					SecurityLogger.logSecurityEvent('INSUFFICIENT_PERMISSIONS', context, { operation });
					return false;
				}
				return true;
				
			default:
				SecurityLogger.logSecurityEvent('UNKNOWN_OPERATION', context, { operation });
				return false;
		}
	}
	
	/**
	 * Check for suspicious user behavior
	 */
	static detectSuspiciousActivity(context: SecurityContext): { suspicious: boolean; reason?: string } {
		// Check for rapid successive requests
		const recentRequests = this.getRecentRequests(context.userId);
		if (recentRequests.length > 50) {
			SecurityLogger.logSecurityEvent('SUSPICIOUS_ACTIVITY', context, { 
				reason: 'High request frequency',
				requestCount: recentRequests.length 
			});
			return { suspicious: true, reason: 'High request frequency detected' };
		}
		
		// Check for operations outside normal hours (if applicable)
		const hour = new Date().getHours();
		if (hour < 6 || hour > 22) {
			SecurityLogger.logSecurityEvent('OFF_HOURS_ACCESS', context, { hour });
		}
		
		return { suspicious: false };
	}
	
	private static getRecentRequests(userId: string): Array<{ timestamp: number }> {
		// Implementation would depend on storage mechanism
		// For now, return empty array as this is a placeholder
		return [];
	}
}

/**
 * Security event logging with KV storage integration
 */
export class SecurityLogger {
	
	/**
	 * Log security events for monitoring with KV persistence
	 */
	static async logSecurityEvent(
		eventType: string, 
		context: SecurityContext, 
		details: Record<string, any> = {},
		kvNamespace?: KVNamespace
	): Promise<void> {
		const securityEvent = {
			timestamp: new Date().toISOString(),
			eventType,
			userId: context.userId,
			provider: context.provider,
			operation: context.operation,
			userAgent: context.userAgent,
			ipAddress: context.ipAddress,
			details,
			severity: this.getEventSeverity(eventType),
			eventId: crypto.randomUUID(),
		};
		
		// Log to console for immediate visibility
		console.warn('SECURITY_EVENT:', JSON.stringify(securityEvent));
		
		// Store events in KV for persistence and analysis
		if (kvNamespace) {
			try {
				const eventKey = `security_event:${securityEvent.eventId}`;
				const userEventKey = `user_events:${context.userId}:${Date.now()}`;
				const severityEventKey = `${securityEvent.severity}_events:${Date.now()}:${securityEvent.eventId}`;
				
				// Store the full event
				await kvNamespace.put(eventKey, JSON.stringify(securityEvent), {
					expirationTtl: 30 * 24 * 60 * 60, // 30 days
					metadata: {
						severity: securityEvent.severity,
						userId: context.userId,
						eventType,
					}
				});
				
				// Store reference for user-based queries
				await kvNamespace.put(userEventKey, securityEvent.eventId, {
					expirationTtl: 30 * 24 * 60 * 60, // 30 days
				});
				
				// Store reference for severity-based queries
				await kvNamespace.put(severityEventKey, securityEvent.eventId, {
					expirationTtl: 7 * 24 * 60 * 60, // 7 days for severity events
				});
				
			} catch (error) {
				console.error('Failed to store security event in KV:', error);
			}
		}
		
		// Store critical events with additional alerting
		if (securityEvent.severity === 'high') {
			await this.storeCriticalEvent(securityEvent, kvNamespace);
		}
	}
	
	/**
	 * Get severity level for event type
	 */
	private static getEventSeverity(eventType: string): 'low' | 'medium' | 'high' {
		const highSeverityEvents = [
			'DANGEROUS_SQL_PATTERN',
			'RATE_LIMIT_EXCEEDED',
			'UNAUTHORIZED_ACCESS',
			'SUSPICIOUS_ACTIVITY'
		];
		
		const mediumSeverityEvents = [
			'POTENTIAL_SQL_INJECTION',
			'INSUFFICIENT_PERMISSIONS',
			'OVERSIZED_SQL_QUERY'
		];
		
		if (highSeverityEvents.includes(eventType)) return 'high';
		if (mediumSeverityEvents.includes(eventType)) return 'medium';
		return 'low';
	}
	
	/**
	 * Store critical security events with enhanced alerting
	 */
	private static async storeCriticalEvent(event: any, kvNamespace?: KVNamespace): Promise<void> {
		// Log to console with special marking
		console.error('CRITICAL_SECURITY_EVENT:', JSON.stringify(event));
		
		// Store in KV with special handling for critical events
		if (kvNamespace) {
			try {
				const criticalKey = `critical_event:${event.eventId}`;
				const alertKey = `security_alert:${Date.now()}`;
				
				// Store critical event with longer retention
				await kvNamespace.put(criticalKey, JSON.stringify(event), {
					expirationTtl: 90 * 24 * 60 * 60, // 90 days for critical events
					metadata: {
						severity: 'critical',
						requiresReview: true,
						userId: event.userId,
					}
				});
				
				// Create alert record for monitoring systems
				const alert = {
					eventId: event.eventId,
					timestamp: event.timestamp,
					eventType: event.eventType,
					userId: event.userId,
					severity: 'critical',
					reviewed: false,
				};
				
				await kvNamespace.put(alertKey, JSON.stringify(alert), {
					expirationTtl: 90 * 24 * 60 * 60, // 90 days
					metadata: {
						alertType: 'security',
						requiresAction: true,
					}
				});
				
			} catch (error) {
				console.error('Failed to store critical security event in KV:', error);
			}
		}
	}

	/**
	 * Retrieve security events for analysis
	 */
	static async getSecurityEvents(
		kvNamespace: KVNamespace,
		options: {
			userId?: string;
			severity?: 'low' | 'medium' | 'high';
			limit?: number;
			since?: Date;
		} = {}
	): Promise<any[]> {
		try {
			const events: any[] = [];
			const limit = options.limit || 100;
			
			// Query based on userId if provided
			if (options.userId) {
				const userEventsList = await kvNamespace.list({
					prefix: `user_events:${options.userId}:`,
					limit,
				});
				
				for (const key of userEventsList.keys) {
					const eventId = await kvNamespace.get(key.name);
					if (eventId) {
						const eventData = await kvNamespace.get(`security_event:${eventId}`);
						if (eventData) {
							events.push(JSON.parse(eventData));
						}
					}
				}
			}
			
			// Query based on severity if provided
			if (options.severity) {
				const severityEventsList = await kvNamespace.list({
					prefix: `${options.severity}_events:`,
					limit,
				});
				
				for (const key of severityEventsList.keys) {
					const eventId = key.name.split(':').pop();
					if (eventId) {
						const eventData = await kvNamespace.get(`security_event:${eventId}`);
						if (eventData) {
							const event = JSON.parse(eventData);
							if (!events.find(e => e.eventId === event.eventId)) {
								events.push(event);
							}
						}
					}
				}
			}
			
			// Filter by date if provided
			if (options.since) {
				return events.filter(event => new Date(event.timestamp) >= options.since!);
			}
			
			return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
			
		} catch (error) {
			console.error('Failed to retrieve security events from KV:', error);
			return [];
		}
	}
}

/**
 * Data sanitization utilities
 */
export class DataSanitizer {
	
	/**
	 * Sanitize output to prevent data leakage
	 */
	static sanitizeOutput(data: any, context: SecurityContext): any {
		if (typeof data === 'string') {
			// Remove potential sensitive patterns
			return data
				.replace(/password\s*[=:]\s*['\"]?[^'\"\s]+['\"]?/gi, 'password=***')
				.replace(/api[_-]?key\s*[=:]\s*['\"]?[^'\"\s]+['\"]?/gi, 'api_key=***')
				.replace(/secret\s*[=:]\s*['\"]?[^'\"\s]+['\"]?/gi, 'secret=***')
				.replace(/token\s*[=:]\s*['\"]?[^'\"\s]+['\"]?/gi, 'token=***');
		}
		
		if (Array.isArray(data)) {
			return data.map(item => this.sanitizeOutput(item, context));
		}
		
		if (typeof data === 'object' && data !== null) {
			const sanitized: any = {};
			for (const [key, value] of Object.entries(data)) {
				// Skip sensitive fields
				if (['password', 'secret', 'token', 'api_key', 'private_key'].includes(key.toLowerCase())) {
					sanitized[key] = '***';
				} else {
					sanitized[key] = this.sanitizeOutput(value, context);
				}
			}
			return sanitized;
		}
		
		return data;
	}
}

/**
 * Configuration for different operations
 */
export const SECURITY_CONFIG = {
	rateLimits: {
		default: { windowMs: 60000, maxRequests: 60 }, // 60 requests per minute
		query: { windowMs: 60000, maxRequests: 30 }, // 30 queries per minute
		execute: { windowMs: 60000, maxRequests: 10 }, // 10 execute operations per minute
		auth: { windowMs: 300000, maxRequests: 5 }, // 5 auth attempts per 5 minutes
	},
	validation: {
		maxSqlLength: 50000,
		maxInputLength: 10000,
	}
} as const;