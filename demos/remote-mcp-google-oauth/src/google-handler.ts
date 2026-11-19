
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { getUpstreamAuthorizeUrl, type Props } from "./utils";
import {
	addApprovedClient,
	bindStateToSession,
	createOAuthState,
	generateCSRFProtection,
	isClientApproved,
	OAuthError,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";

const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>();

const YOUTUBE_SCOPES = [
	"email",
	"profile",
	"https://www.googleapis.com/auth/yt-analytics.readonly",
	"https://www.googleapis.com/auth/youtube.readonly",
];

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	const { clientId } = oauthReqInfo;

	if (!clientId) return c.text("Invalid request", 400);

	if (await isClientApproved(c.req.raw, clientId, c.env.COOKIE_ENCRYPTION_KEY)) {
		const { stateToken } = await createOAuthState(oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie } = await bindStateToSession(stateToken);
		const headers = new Headers();
		headers.append("Set-Cookie", setCookie);

		return redirectToGoogle(c.req.raw, c.env, stateToken, headers);
	}

	const { token: csrfToken, setCookie } = generateCSRFProtection();

	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		csrfToken,
		server: {
			description: "Read-only YouTube Analytics and channel information.",
			name: "Silent Patterns YouTube MCP",
		},
		setCookie,
		state: { oauthReqInfo },
	});
});

app.post("/authorize", async (c) => {
	try {
		const formData = await c.req.raw.formData();
		validateCSRFToken(formData, c.req.raw);

		const encodedState = formData.get("state");
		if (!encodedState || typeof encodedState !== "string") {
			return c.text("Missing state in form data", 400);
		}

		let state: { oauthReqInfo?: AuthRequest };
		try {
			state = JSON.parse(atob(encodedState));
		} catch {
			return c.text("Invalid state data", 400);
		}

		if (!state.oauthReqInfo?.clientId) {
			return c.text("Invalid request", 400);
		}

		const approvedClientCookie = await addApprovedClient(
			c.req.raw,
			state.oauthReqInfo.clientId,
			c.env.COOKIE_ENCRYPTION_KEY,
		);

		const { stateToken } = await createOAuthState(
			state.oauthReqInfo,
			c.env.OAUTH_KV,
		);

		const { setCookie: sessionBindingCookie } =
			await bindStateToSession(stateToken);

		const headers = new Headers();
		headers.append("Set-Cookie", approvedClientCookie);
		headers.append("Set-Cookie", sessionBindingCookie);

		return redirectToGoogle(c.req.raw, c.env, stateToken, headers);
	} catch (error: unknown) {
		console.error("POST /authorize error:", error);
		if (error instanceof OAuthError) return error.toResponse();
		return c.text("Internal server error", 500);
	}
});

function redirectToGoogle(
	request: Request,
	env: Env,
	stateToken: string,
	extraHeaders: HeadersInit = {},
) {
	const url = new URL(
		getUpstreamAuthorizeUrl({
			clientId: env.GOOGLE_CLIENT_ID,
			hostedDomain: undefined,
			redirectUri: new URL("/callback", request.url).href,
			scope: YOUTUBE_SCOPES.join(" "),
			state: stateToken,
			upstreamUrl: "https://accounts.google.com/o/oauth2/v2/auth",
		}),
	);

	url.searchParams.set("access_type", "offline");
	url.searchParams.set("prompt", "consent");

	const headers = new Headers(extraHeaders);
	headers.set("Location", url.href);

	return new Response(null, { status: 302, headers });
}

app.get("/callback", async (c) => {
	let oauthReqInfo: AuthRequest;
	let clearSessionCookie: string;

	try {
		const result = await validateOAuthState(c.req.raw, c.env.OAUTH_KV);
		oauthReqInfo = result.oauthReqInfo;
		clearSessionCookie = result.clearCookie;
	} catch (error: unknown) {
		if (error instanceof OAuthError) return error.toResponse();
		return c.text("Internal server error", 500);
	}

	if (!oauthReqInfo.clientId) {
		return c.text("Invalid OAuth request data", 400);
	}

	const googleError = c.req.query("error");
	if (googleError) {
		return c.text(`Google authorization failed: ${googleError}`, 400);
	}

	const code = c.req.query("code");
	if (!code) return c.text("Missing code", 400);

	const redirectUri = new URL("/callback", c.req.url).href;

	const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			client_id: c.env.GOOGLE_CLIENT_ID,
			client_secret: c.env.GOOGLE_CLIENT_SECRET,
			code,
			grant_type: "authorization_code",
			redirect_uri: redirectUri,
		}),
	});

	if (!tokenResponse.ok) {
		console.error("Google token exchange failed:", await tokenResponse.text());
		return c.text("Failed to obtain Google access token", 500);
	}

	const tokens = await tokenResponse.json() as {
		access_token?: string;
		refresh_token?: string;
	};

	if (!tokens.access_token || !tokens.refresh_token) {
		return c.text(
			"Google did not return both required tokens. Revoke the previous app grant and authorize again.",
			400,
		);
	}

	const userResponse = await fetch(
		"https://www.googleapis.com/oauth2/v2/userinfo",
		{
			headers: { Authorization: `Bearer ${tokens.access_token}` },
		},
	);

	if (!userResponse.ok) {
		return c.text("Failed to fetch Google user information", 500);
	}

	const user = await userResponse.json() as {
		id: string;
		name: string;
		email: string;
	};

	const props: Props = {
		accessToken: tokens.access_token,
		refreshToken: tokens.refresh_token,
		email: user.email,
		name: user.name,
	};

	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		metadata: { label: user.name },
		props,
		request: oauthReqInfo,
		scope: oauthReqInfo.scope,
		userId: user.id,
	});

	const headers = new Headers({ Location: redirectTo });
	if (clearSessionCookie) {
		headers.append("Set-Cookie", clearSessionCookie);
	}

	return new Response(null, { status: 302, headers });
});

export { app as GoogleHandler };
