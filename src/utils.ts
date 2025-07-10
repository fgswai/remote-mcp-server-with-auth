/**
 * Constructs an authorization URL for an upstream service.
 *
 * @param {Object} options
 * @param {string} options.upstream_url - The base URL of the upstream service.
 * @param {string} options.client_id - The client ID of the application.
 * @param {string} options.redirect_uri - The redirect URI of the application.
 * @param {string} [options.state] - The state parameter.
 *
 * @returns {string} The authorization URL.
 */
export function getUpstreamAuthorizeUrl({
	upstream_url,
	client_id,
	scope,
	redirect_uri,
	state,
}: {
	upstream_url: string;
	client_id: string;
	scope: string;
	redirect_uri: string;
	state?: string;
}) {
	const upstream = new URL(upstream_url);
	upstream.searchParams.set("client_id", client_id);
	upstream.searchParams.set("redirect_uri", redirect_uri);
	upstream.searchParams.set("scope", scope);
	if (state) upstream.searchParams.set("state", state);
	upstream.searchParams.set("response_type", "code");
	return upstream.href;
}

/**
 * Fetches an authorization token from an upstream Git service.
 * Enhanced to handle different response formats across Git providers.
 *
 * @param {Object} options
 * @param {string} options.client_id - The client ID of the application.
 * @param {string} options.client_secret - The client secret of the application.
 * @param {string} options.code - The authorization code.
 * @param {string} options.redirect_uri - The redirect URI of the application.
 * @param {string} options.upstream_url - The token endpoint URL of the upstream service.
 * @param {string} [options.grant_type] - The grant type (defaults to 'authorization_code').
 *
 * @returns {Promise<[string, null] | [null, Response]>} A promise that resolves to an array containing the access token or an error response.
 */
export async function fetchUpstreamAuthToken({
	client_id,
	client_secret,
	code,
	redirect_uri,
	upstream_url,
	grant_type = "authorization_code",
}: {
	code: string | undefined;
	upstream_url: string;
	client_secret: string;
	redirect_uri: string;
	client_id: string;
	grant_type?: string;
}): Promise<[string, null] | [null, Response]> {
	if (!code) {
		return [null, new Response("Missing authorization code", { status: 400 })];
	}

	try {
		// Prepare request body for OAuth token exchange
		const requestBody = new URLSearchParams({ 
			client_id, 
			client_secret, 
			code, 
			redirect_uri,
			grant_type 
		}).toString();

		const resp = await fetch(upstream_url, {
			body: requestBody,
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept": "application/json", // Prefer JSON responses
				"User-Agent": "Supabase-MCP-Server/1.0",
			},
			method: "POST",
		});

		if (!resp.ok) {
			const errorText = await resp.text();
			console.error(`Token exchange failed (${resp.status}):`, errorText);
			return [null, new Response(`Failed to fetch access token: ${resp.statusText}`, { status: 500 })];
		}

		const contentType = resp.headers.get("content-type");
		let accessToken: string | null = null;

		// Handle different response formats from various Git providers
		if (contentType?.includes("application/json")) {
			// JSON response (GitLab, Bitbucket, newer GitHub API)
			const jsonBody = await resp.json();
			accessToken = jsonBody.access_token;
		} else {
			// Form data response (GitHub traditional, some others)
			try {
				const formBody = await resp.formData();
				accessToken = formBody.get("access_token") as string;
			} catch (formError) {
				// Fallback: try to parse as URL-encoded string
				const textBody = await resp.text();
				const params = new URLSearchParams(textBody);
				accessToken = params.get("access_token");
			}
		}

		if (!accessToken) {
			console.error("No access token found in response");
			return [null, new Response("Missing access token in provider response", { status: 400 })];
		}

		return [accessToken, null];
	} catch (error) {
		console.error("Token exchange error:", error);
		return [null, new Response("Token exchange failed due to network or parsing error", { status: 500 })];
	}
}

// Context from the auth process, encrypted & stored in the auth token
// and provided to the DurableMCP as this.props
// Enhanced to support multiple Git providers (GitHub, GitLab, Bitbucket, etc.)
export type Props = {
	login: string;
	name: string;
	email: string;
	accessToken: string;
	provider: string; // github, gitlab, bitbucket, etc.
	avatar_url?: string;
	user_id: string | number;
};
