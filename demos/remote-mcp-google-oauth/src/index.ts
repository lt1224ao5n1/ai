
import { env } from "cloudflare:workers";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import { z } from "zod";
import { GoogleHandler } from "./google-handler";
import type { Props } from "./utils";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const YOUTUBE_API = "https://www.googleapis.com/youtube/v3";
const ANALYTICS_API = "https://youtubeanalytics.googleapis.com/v2/reports";

async function getGoogleAccessToken(props: Props): Promise<string> {
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: props.refreshToken,
      grant_type: "refresh_token",
    }),
  });

  if (!response.ok) {
    throw new Error("Google token refresh failed. Please reconnect your Google account.");
  }

  const data = await response.json() as { access_token?: string };

  if (!data.access_token) {
    throw new Error("Google did not return an access token.");
  }

  return data.access_token;
}

async function googleGet(
  url: string,
  accessToken: string
): Promise<any> {
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`Google API error (${response.status}): ${message}`);
  }

  return response.json();
}

function createServer() {
  const server = new McpServer({
    name: "Silent Patterns YouTube Analytics",
    version: "1.0.0",
  });

  const props = getMcpAuthContext()?.props as Props | undefined;

  async function token() {
    if (!props?.refreshToken) {
      throw new Error("Google account is not connected. Please reconnect.");
    }
    return getGoogleAccessToken(props);
  }

  server.registerTool(
    "get_channel_overview",
    {
      description: "Get the authenticated YouTube channel name, views, subscribers and video count.",
    },
    async () => {
      try {
        const accessToken = await token();
        const url = `${YOUTUBE_API}/channels?part=snippet,statistics&mine=true`;
        const data = await googleGet(url, accessToken);
        const channel = data.items?.[0];

        if (!channel) {
          throw new Error("No YouTube channel was found for this Google account.");
        }

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              channelName: channel.snippet?.title,
              channelId: channel.id,
              subscribers: channel.statistics?.subscriberCount,
              totalViews: channel.statistics?.viewCount,
              videoCount: channel.statistics?.videoCount,
              hiddenSubscriberCount: channel.statistics?.hiddenSubscriberCount,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: "text", text: String(error) }],
        };
      }
    }
  );

  server.registerTool(
    "get_analytics_report",
    {
      description: "Get YouTube channel analytics for a date range. Dates must use YYYY-MM-DD format.",
      inputSchema: z.object({
        startDate: z.string(),
        endDate: z.string(),
      }),
    },
    async ({ startDate, endDate }) => {
      try {
        if (startDate > endDate) {
          throw new Error("startDate must be before or equal to endDate.");
        }

        const accessToken = await token();
        const params = new URLSearchParams({
          ids: "channel==MINE",
          startDate,
          endDate,
          metrics: "views,estimatedMinutesWatched,averageViewDuration,subscribersGained,subscribersLost",
        });

        const data = await googleGet(
          `${ANALYTICS_API}?${params.toString()}`,
          accessToken
        );

        return {
          content: [{
            type: "text",
            text: JSON.stringify(data, null, 2),
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: "text", text: String(error) }],
        };
      }
    }
  );

  server.registerTool(
    "get_top_videos",
    {
      description: "Get the most viewed YouTube videos in a date range. Dates must use YYYY-MM-DD format.",
      inputSchema: z.object({
        startDate: z.string(),
        endDate: z.string(),
      }),
    },
    async ({ startDate, endDate }) => {
      try {
        if (startDate > endDate) {
          throw new Error("startDate must be before or equal to endDate.");
        }

        const accessToken = await token();
        const params = new URLSearchParams({
          ids: "channel==MINE",
          startDate,
          endDate,
          metrics: "views,estimatedMinutesWatched,averageViewDuration",
          dimensions: "video",
          sort: "-views",
          maxResults: "10",
        });

        const data = await googleGet(
          `${ANALYTICS_API}?${params.toString()}`,
          accessToken
        );

        return {
          content: [{
            type: "text",
            text: JSON.stringify(data, null, 2),
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: "text", text: String(error) }],
        };
      }
    }
  );

  return server;
}

const mcpHandler = createMcpHandler(createServer);

export default new OAuthProvider<Env>({
  apiHandler: {
    fetch(request, env, ctx) {
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
