import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { fetchUpstreamAuthToken, getUpstreamAuthorizeUrl, type Props } from "./utils";
import {
	clientIdAlreadyApproved,
	parseRedirectApproval,
	renderApprovalDialog,
} from "./workers-oauth-utils";

type ExtendedEnv = Env & { OAUTH_PROVIDER: OAuthHelpers };
const app = new Hono<{ Bindings: ExtendedEnv }>();

// Git provider configurations
interface GitProvider {
	name: string;
	authorizeUrl: string;
	tokenUrl: string;
	userApiUrl: string;
	scope: string;
	logo: string;
}

const GIT_PROVIDERS: Record<string, GitProvider> = {
	github: {
		name: "GitHub",
		authorizeUrl: "https://github.com/login/oauth/authorize",
		tokenUrl: "https://github.com/login/oauth/access_token",
		userApiUrl: "https://api.github.com/user",
		scope: "read:user user:email",
		logo: "https://avatars.githubusercontent.com/u/9919?s=200&v=4"
	},
	gitlab: {
		name: "GitLab",
		authorizeUrl: "https://gitlab.com/oauth/authorize",
		tokenUrl: "https://gitlab.com/oauth/token",
		userApiUrl: "https://gitlab.com/api/v4/user",
		scope: "read_user read_api",
		logo: "https://about.gitlab.com/images/press/logo/png/gitlab-logo-gray-rgb.png"
	},
	bitbucket: {
		name: "Bitbucket",
		authorizeUrl: "https://bitbucket.org/site/oauth2/authorize",
		tokenUrl: "https://bitbucket.org/site/oauth2/access_token",
		userApiUrl: "https://api.bitbucket.org/2.0/user",
		scope: "account",
		logo: "https://wac-cdn.atlassian.com/dam/jcr:e2a6f06f-b3d5-4002-aed3-73539c56a2eb/bitbucket_rgb_blue.png"
	}
};

/**
 * Get the Git provider configuration based on environment variable
 */
function getGitProvider(env: any): GitProvider {
	const providerName = env.GIT_PROVIDER || 'github';
	const provider = GIT_PROVIDERS[providerName.toLowerCase()];
	
	if (!provider) {
		throw new Error(`Unsupported Git provider: ${providerName}. Supported providers: ${Object.keys(GIT_PROVIDERS).join(', ')}`);
	}
	
	return provider;
}

/**
 * Get OAuth client credentials based on provider
 */
function getOAuthCredentials(env: any) {
	const provider = getGitProvider(env);
	
	// Check for provider-specific credentials first, then fall back to GIT_* credentials
	const clientId = env[`${provider.name.toUpperCase()}_CLIENT_ID`] || env.GIT_CLIENT_ID;
	const clientSecret = env[`${provider.name.toUpperCase()}_CLIENT_SECRET`] || env.GIT_CLIENT_SECRET;
	
	if (!clientId || !clientSecret) {
		throw new Error(`Missing OAuth credentials for ${provider.name}. Set GIT_CLIENT_ID and GIT_CLIENT_SECRET environment variables.`);
	}
	
	return { clientId, clientSecret };
}

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	const { clientId } = oauthReqInfo;
	if (!clientId) {
		return c.text("Invalid request", 400);
	}

	if (
		await clientIdAlreadyApproved(c.req.raw, oauthReqInfo.clientId, (c.env as any).COOKIE_ENCRYPTION_KEY)
	) {
		return redirectToGitProvider(c.req.raw, oauthReqInfo, c.env, {});
	}

	const provider = getGitProvider(c.env);
	
	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		server: {
			description: `This is a Supabase MCP Server using ${provider.name} for authentication.`,
			logo: provider.logo,
			name: `Supabase MCP Server (${provider.name})`,
		},
		state: { oauthReqInfo },
	});
});

app.post("/authorize", async (c) => {
	// Validates form submission, extracts state, and generates Set-Cookie headers to skip approval dialog next time
	const { state, headers } = await parseRedirectApproval(c.req.raw, (c.env as any).COOKIE_ENCRYPTION_KEY);
	if (!state.oauthReqInfo) {
		return c.text("Invalid request", 400);
	}

	return redirectToGitProvider(c.req.raw, state.oauthReqInfo, c.env, headers);
});

async function redirectToGitProvider(
	request: Request,
	oauthReqInfo: AuthRequest,
	env: Env,
	headers: Record<string, string> = {},
) {
	const provider = getGitProvider(env);
	const { clientId } = getOAuthCredentials(env);
	
	return new Response(null, {
		headers: {
			...headers,
			location: getUpstreamAuthorizeUrl({
				client_id: clientId,
				redirect_uri: new URL("/callback", request.url).href,
				scope: provider.scope,
				state: btoa(JSON.stringify(oauthReqInfo)),
				upstream_url: provider.authorizeUrl,
			}),
		},
		status: 302,
	});
}

/**
 * Generic user info fetcher for different Git providers
 */
async function fetchUserInfo(accessToken: string, provider: GitProvider) {
	const response = await fetch(provider.userApiUrl, {
		headers: {
			Authorization: `Bearer ${accessToken}`,
			"User-Agent": "Supabase-MCP-Server/1.0",
			"Accept": "application/json",
		},
	});

	if (!response.ok) {
		throw new Error(`Failed to fetch user info from ${provider.name}: ${response.statusText}`);
	}

	const userData = await response.json();
	
	// Normalize user data across different providers
	let normalizedUser;
	
	switch (provider.name.toLowerCase()) {
		case 'github':
			normalizedUser = {
				login: userData.login,
				name: userData.name || userData.login,
				email: userData.email,
				avatar_url: userData.avatar_url,
				id: userData.id,
				provider: 'github'
			};
			break;
			
		case 'gitlab':
			normalizedUser = {
				login: userData.username,
				name: userData.name || userData.username,
				email: userData.email,
				avatar_url: userData.avatar_url,
				id: userData.id,
				provider: 'gitlab'
			};
			break;
			
		case 'bitbucket':
			normalizedUser = {
				login: userData.username,
				name: userData.display_name || userData.username,
				email: userData.email,
				avatar_url: userData.links?.avatar?.href,
				id: userData.uuid,
				provider: 'bitbucket'
			};
			break;
			
		default:
			throw new Error(`Unsupported provider for user normalization: ${provider.name}`);
	}
	
	return normalizedUser;
}

/**
 * OAuth Callback Endpoint
 *
 * This route handles the callback from any supported Git provider after user authentication.
 * It exchanges the temporary code for an access token, then stores some
 * user metadata & the auth token as part of the 'props' on the token passed
 * down to the client. It ends by redirecting the client back to _its_ callback URL
 */
app.get("/callback", async (c) => {
	try {
		// Get the oauthReqInfo out of state
		const oauthReqInfo = JSON.parse(atob(c.req.query("state") as string)) as AuthRequest;
		if (!oauthReqInfo.clientId) {
			return c.text("Invalid state", 400);
		}

		const provider = getGitProvider(c.env);
		const { clientId, clientSecret } = getOAuthCredentials(c.env);
		
		// Exchange the code for an access token
		const [accessToken, errResponse] = await fetchUpstreamAuthToken({
			client_id: clientId,
			client_secret: clientSecret,
			code: c.req.query("code"),
			redirect_uri: new URL("/callback", c.req.url).href,
			upstream_url: provider.tokenUrl,
		});
		
		if (errResponse) return errResponse;

		// Fetch the user info from the Git provider
		const user = await fetchUserInfo(accessToken, provider);

		// Return back to the MCP client a new token
		const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
			metadata: {
				label: `${user.name} (${provider.name})`,
			},
			// This will be available on this.props inside MyMCP
			props: {
				accessToken,
				email: user.email,
				login: user.login,
				name: user.name,
				provider: user.provider,
				avatar_url: user.avatar_url,
				user_id: user.id
			} as Props,
			request: oauthReqInfo,
			scope: oauthReqInfo.scope,
			userId: `${user.provider}:${user.login}`,
		});

		return Response.redirect(redirectTo);
	} catch (error) {
		console.error('Git OAuth callback error:', error);
		return c.text(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`, 500);
	}
});

export { app as GitHandler };