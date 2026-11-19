
import { env } from "cloudflare:workers";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import { z } from "zod";
import { GoogleHandler } from "./google-handler";

export type Props = {
	name: string;
	email: string;
	accessToken: string;
	refreshToken: string;
};

function createServer() {
	const server = new McpServer({
		name: "Silent Patterns YouTube Analytics",
		version: "1.0.0",
	});

	server.registerTool(
		"who_am_i",
		{
			description: "Returns the Google account authenticated with this server.",
			inputSchema: z.object({}),
		},
		async () => {
			const props = getMcpAuthContext()?.props as Props | undefined;

			if (!props) {
				return {
					isError: true,
					content: [{ type: "text", text: "Google authentication is missing." }],
				};
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
