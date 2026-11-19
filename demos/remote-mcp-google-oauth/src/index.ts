
import { env } from "cloudflare:workers";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import {
	createMcpHandler,
	getMcpAuthContext,
} from "agents/mcp/server";
import { z } from "zod";
import { GoogleHandler } from "./google-handler";

export type Props = {
	name: string;
	email: string;
	accessToken: string;
	refreshToken: string;
};

async function getGoogleAccessToken(): Promise<string> {
	const props = getMcpAuthContext()?.props as Props | undefined;

	if (!props?.accessToken || !props.refreshToken) {
		throw new Error("Google account is not authenticated.");
	}

	const response = await fetch(
		"https://oauth2.googleapis.com/token",
		{
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				client_id: env.GOOGLE_CLIENT_ID,
				client_secret: env.GOOGLE_CLIENT_SECRET,
				refresh_token: props.refreshToken,
				grant_type: "refresh_token",
			}),
		},
	);

	if (!response.ok) {
		throw new Error("Could not refresh Google access token.");
	}

	const data = await response.json() as {
		access_token?: string;
	};

	if (!data.access_token) {
		throw new Error("Google did not return an access token.");
	}

	return data.access_token;
}

async function googleGet(url: string) {
	const accessToken = await getGoogleAccessToken();

	const response = await fetch(url, {
		headers: {
			Authorization: `Bearer ${accessToken}`,
		},
	});

	if (!response.ok) {
		throw new Error(
			`Google API error ${response.status}: ${await response.text()}`,
		);
	}

	return response.json();
}

function createServer() {
	const server = new McpServer({
		name: "Silent Patterns YouTube Analytics",
		version: "1.0.0",
	});

	server.registerTool(
		"who_am_i",
		{
			description: "Shows the Google account connected to this server.",
			inputSchema: z.object({}),
		},
		async () => {
			const props = getMcpAuthContext()?.props as Props | undefined;

			if (!props) {
				throw new Error("Google authentication is missing.");
			}

			return {
				content: [{
					type: "text",
					text: JSON.stringify({
						name: props.name,
						email: props.email,
					}),
				}],
			};
		},
	);

	server.registerTool(
		"get_youtube_channel",
		{
			description: "Gets the authenticated YouTube channel details.",
			inputSchema: z.object({}),
		},
		async () => {
			const data = await googleGet(
				"https://www.googleapis.com/youtube/v3/channels?part=snippet,statistics&mine=true",
			);

			return {
				content: [{
					type: "text",
					text: JSON.stringify(data, null, 2),
				}],
			};
		},
	);

	server.registerTool(
		"get_channel_analytics",
		{
			description: "Gets YouTube channel views, watch time, subscribers and average view duration for a date range.",
			inputSchema: z.object({
				startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
				endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
			}),
		},
		async ({ startDate, endDate }) => {
			if (startDate > endDate) {
				throw new Error("Start date must be before end date.");
			}

			const params = new URLSearchParams({
				ids: "channel==MINE",
				startDate,
				endDate,
				metrics: "views,estimatedMinutesWatched,subscribersGained,averageViewDuration",
			});

			const data = await googleGet(
				`https://youtubeanalytics.googleapis.com/v2/reports?${params}`,
			);

			return {
				content: [{
					type: "text",
					text: JSON.stringify(data, null, 2),
				}],
			};
		},
	);

	server.registerTool(
		"get_top_videos",
		{
			description: "Gets the top YouTube videos by views for a date range.",
			inputSchema: z.object({
				startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
				endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
				maxResults: z.number().int().min(1).max(50).default(10),
			}),
		},
		async ({ startDate, endDate, maxResults }) => {
			if (startDate > endDate) {
				throw new Error("Start date must be before end date.");
			}

			const params = new URLSearchParams({
				ids: "channel==MINE",
				startDate,
				endDate,
				metrics: "views,estimatedMinutesWatched,averageViewDuration,likes,subscribersGained",
				dimensions: "video",
				sort: "-views",
				maxResults: String(maxResults),
			});

			const data = await googleGet(
				`https://youtubeanalytics.googleapis.com/v2/reports?${params}`,
			);

			return {
				content: [{
					type: "text",
					text: JSON.stringify(data, null, 2),
				}],
			};
		},
	);

	return server;
}

const mcpHandler = createMcpHandler(createServer);

export default new OAuthProvider<Env>({
	apiHandler: {
		fetch(request: Request, env: Env, ctx: ExecutionContext) {
			return mcpHandler(request, env, ctx);
		},
	},
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: GoogleHandler as any,
	tokenEndpoint: "/token",
	resourceMetadata: { resource: env.MCP_RESOURCE },
});
