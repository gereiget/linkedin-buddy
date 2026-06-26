const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const tokenStorePath =
  process.env.TOKEN_STORE_PATH || path.join(__dirname, "data", "token-store.json");
const appSessionCookieName = "linkedin_buddy_session";
const configuredAppSessionHours = Number(process.env.APP_SESSION_DURATION_HOURS || 12);
const appSessionDurationMs =
  (Number.isFinite(configuredAppSessionHours) && configuredAppSessionHours > 0
    ? configuredAppSessionHours
    : 12) *
  60 *
  60 *
  1000;
const appLoginUsername = process.env.APP_LOGIN_USERNAME || "admin";
const appLoginPassword = process.env.APP_LOGIN_PASSWORD || "";
const appSessionSecret = process.env.APP_SESSION_SECRET || "";
const appCookieSecure =
  String(process.env.APP_COOKIE_SECURE || "").toLowerCase() === "true";

const requiredEnvVars = [
  "LINKEDIN_CLIENT_ID",
  "LINKEDIN_CLIENT_SECRET",
  "LINKEDIN_REDIRECT_URI",
  "LINKEDIN_VERSION",
];

const defaultScopes = [
  "rw_organization_admin",
  "r_organization_social",
  "w_organization_social",
];

const scopes = (process.env.LINKEDIN_SCOPES || defaultScopes.join(","))
  .split(",")
  .map((scope) => scope.trim())
  .filter(Boolean);

let tokenStore = loadTokenStore();
let oauthState = null;

function ensureStoreDirectory() {
  fs.mkdirSync(path.dirname(tokenStorePath), { recursive: true });
}

function createEmptyTokenStore() {
  return {
    accessToken: null,
    grantedScopes: [],
    tokenResponse: null,
    savedAt: null,
    lastResults: null,
    followerHistory: {},
    postHistory: [],
  };
}

function loadTokenStore() {
  try {
    if (!fs.existsSync(tokenStorePath)) {
      return createEmptyTokenStore();
    }

    const fileContent = fs.readFileSync(tokenStorePath, "utf8");
    const parsed = JSON.parse(fileContent);

    return {
      ...createEmptyTokenStore(),
      ...parsed,
    };
  } catch (error) {
    console.warn("Failed to load token store:", error.message);
    return createEmptyTokenStore();
  }
}

function persistTokenStore() {
  try {
    ensureStoreDirectory();
    fs.writeFileSync(tokenStorePath, JSON.stringify(tokenStore, null, 2));
  } catch (error) {
    console.warn("Failed to persist token store:", error.message);
  }
}

function resetTokenStore() {
  tokenStore = createEmptyTokenStore();
  persistTokenStore();
}

function getMissingEnvVars() {
  return requiredEnvVars.filter((key) => !process.env[key]);
}

function buildAuthorizationUrl() {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
    scope: scopes.join(" "),
    state: oauthState,
  });

  return `https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`;
}

function getRestHeaders(accessToken) {
  return {
    Authorization: `Bearer ${accessToken}`,
    "Linkedin-Version": process.env.LINKEDIN_VERSION,
    "X-Restli-Protocol-Version": "2.0.0",
  };
}

function normalizeError(error) {
  if (error.response) {
    return {
      message: error.message,
      status: error.response.status,
      statusText: error.response.statusText,
      data: error.response.data,
      headers: error.response.headers,
    };
  }

  return {
    message: error.message,
    status: null,
    statusText: null,
    data: null,
  };
}

function parseGrantedScopes(scopeValue) {
  return String(scopeValue || "")
    .split(/[,\s]+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function safeJsonForHtml(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function parseCookies(cookieHeader) {
  return String(cookieHeader || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, part) => {
      const separatorIndex = part.indexOf("=");
      if (separatorIndex === -1) {
        return cookies;
      }

      const key = part.slice(0, separatorIndex).trim();
      const value = part.slice(separatorIndex + 1).trim();
      try {
        cookies[key] = decodeURIComponent(value);
      } catch (error) {
        cookies[key] = value;
      }
      return cookies;
    }, {});
}

function isAppLoginConfigured() {
  return Boolean(appLoginPassword && appSessionSecret);
}

function getAppLoginConfigError() {
  if (isAppLoginConfigured()) {
    return null;
  }

  return "Missing app login configuration. Set APP_LOGIN_PASSWORD and APP_SESSION_SECRET before exposing this dashboard publicly.";
}

function createSessionSignature(payload) {
  return crypto
    .createHmac("sha256", appSessionSecret)
    .update(payload)
    .digest("hex");
}

function createAppSessionValue(username) {
  const expiresAt = Date.now() + appSessionDurationMs;
  const payload = `${username}:${expiresAt}`;
  const signature = createSessionSignature(payload);
  return Buffer.from(`${payload}:${signature}`, "utf8").toString("base64url");
}

function verifySessionSignature(payload, signature) {
  const expected = createSessionSignature(payload);
  const expectedBuffer = Buffer.from(expected, "utf8");
  const providedBuffer = Buffer.from(String(signature || ""), "utf8");

  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}

function readAppSession(req) {
  if (!isAppLoginConfigured()) {
    return { ok: false, error: getAppLoginConfigError() };
  }

  try {
    const cookies = parseCookies(req.headers.cookie);
    const rawValue = cookies[appSessionCookieName];
    if (!rawValue) {
      return { ok: false, error: "Missing app session cookie." };
    }

    const decoded = Buffer.from(rawValue, "base64url").toString("utf8");
    const lastSeparatorIndex = decoded.lastIndexOf(":");
    const firstSeparatorIndex = decoded.indexOf(":");

    if (firstSeparatorIndex === -1 || lastSeparatorIndex === -1) {
      return { ok: false, error: "Malformed app session cookie." };
    }

    const payload = decoded.slice(0, lastSeparatorIndex);
    const signature = decoded.slice(lastSeparatorIndex + 1);
    const username = decoded.slice(0, firstSeparatorIndex);
    const expiresAt = Number(decoded.slice(firstSeparatorIndex + 1, lastSeparatorIndex));

    if (!verifySessionSignature(payload, signature)) {
      return { ok: false, error: "Invalid app session signature." };
    }

    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      return { ok: false, error: "App session expired." };
    }

    if (username !== appLoginUsername) {
      return { ok: false, error: "Invalid app session user." };
    }

    return {
      ok: true,
      username,
      expiresAt,
    };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function setAppSessionCookie(res, username) {
  const cookieValue = createAppSessionValue(username);
  const attributes = [
    `${appSessionCookieName}=${encodeURIComponent(cookieValue)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(appSessionDurationMs / 1000)}`,
  ];

  if (appCookieSecure) {
    attributes.push("Secure");
  }

  res.setHeader("Set-Cookie", attributes.join("; "));
}

function clearAppSessionCookie(res) {
  const attributes = [
    `${appSessionCookieName}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
  ];

  if (appCookieSecure) {
    attributes.push("Secure");
  }

  res.setHeader("Set-Cookie", attributes.join("; "));
}

function isBrowserRequest(req) {
  return String(req.headers.accept || "").includes("text/html");
}

function makeSkippedResult(note) {
  return {
    attempted: false,
    note,
  };
}

function findOrganizationByUrn(organizationUrn) {
  return (tokenStore.lastResults?.organizations || []).find(
    (organization) => organization.organizationUrn === organizationUrn
  );
}

function getOrganizationDisplayName(organization) {
  return (
    organization?.name ||
    organization?.vanityName ||
    organization?.organizationUrn ||
    "Unknown organization"
  );
}

function buildPostValidationError(message, status = 400) {
  const statusTextMap = {
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
  };

  return {
    ok: false,
    error: {
      message,
      status,
      statusText: statusTextMap[status] || "Bad Request",
      data: null,
    },
  };
}

function validateOrganizationPostInput({ organizationUrn, commentary, lifecycleState }) {
  if (!organizationUrn) {
    return buildPostValidationError(
      "Missing organizationUrn. Example: urn:li:organization:123456"
    );
  }

  if (!commentary || !String(commentary).trim()) {
    return buildPostValidationError("Post text is required.");
  }

  const trimmedCommentary = String(commentary).trim();
  if (trimmedCommentary.length > 3000) {
    return buildPostValidationError(
      "Post text exceeds the 3000 character limit enforced by this dashboard."
    );
  }

  const normalizedLifecycleState =
    lifecycleState === "DRAFT" ? "DRAFT" : "PUBLISHED";

  const organization = findOrganizationByUrn(organizationUrn);
  if (!organization) {
    return buildPostValidationError(
      "This organization is not available in the current authenticated session.",
      404
    );
  }

  if (organization.state !== "APPROVED") {
    return buildPostValidationError(
      "LinkedIn does not list this organization as APPROVED for the current token.",
      403
    );
  }

  return {
    ok: true,
    organization,
    normalizedCommentary: trimmedCommentary,
    normalizedLifecycleState,
  };
}

function recordPostResult(postResult) {
  tokenStore.postHistory = tokenStore.postHistory || [];
  tokenStore.postHistory.unshift({
    attemptedAt: new Date().toISOString(),
    ...postResult,
  });
  tokenStore.postHistory = tokenStore.postHistory.slice(0, 20);
  persistTokenStore();
}

function invalidateOrganizationPostCache(organizationUrn) {
  if (!tokenStore.lastResults?.organizations?.length) {
    return;
  }

  tokenStore.lastResults.organizations = tokenStore.lastResults.organizations.map(
    (organization) =>
      organization.organizationUrn === organizationUrn
        ? {
            ...organization,
            organizationPostsResult: null,
            publishedPosts: undefined,
          }
        : organization
  );
}

function buildDraftTestCommentary(organizationUrn) {
  const timestamp = new Date().toISOString();
  const organizationId = String(organizationUrn || "").split(":").pop() || "unknown";
  return `Test draft post from local LinkedIn API utility. Org ${organizationId}. ${timestamp}`;
}

async function fetchUserInfo(accessToken) {
  try {
    const response = await axios.get("https://api.linkedin.com/v2/userinfo", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchLiteProfile(accessToken) {
  try {
    const response = await axios.get(
      "https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchEmailAddress(accessToken) {
  try {
    const response = await axios.get(
      "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationAcls(accessToken) {
  try {
    const response = await axios.get(
      "https://api.linkedin.com/rest/organizationAcls?q=roleAssignee&role=ADMINISTRATOR",
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationDetails(accessToken, organizationId) {
  try {
    const response = await axios.get(
      `https://api.linkedin.com/rest/organizations/${organizationId}`,
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationFollowerCount(accessToken, organizationUrn) {
  try {
    const encodedUrn = encodeURIComponent(organizationUrn);
    const response = await axios.get(
      `https://api.linkedin.com/rest/networkSizes/${encodedUrn}?edgeType=COMPANY_FOLLOWED_BY_MEMBER`,
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationFollowerDemographics(accessToken, organizationUrn) {
  try {
    const encodedUrn = encodeURIComponent(organizationUrn);
    const response = await axios.get(
      `https://api.linkedin.com/rest/organizationalEntityFollowerStatistics?q=organizationalEntity&organizationalEntity=${encodedUrn}`,
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationPageStatistics(accessToken, organizationUrn) {
  try {
    const encodedUrn = encodeURIComponent(organizationUrn);
    const response = await axios.get(
      `https://api.linkedin.com/rest/organizationPageStatistics?q=organization&organization=${encodedUrn}`,
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationShareStatistics(accessToken, organizationUrn) {
  try {
    const encodedUrn = encodeURIComponent(organizationUrn);
    const response = await axios.get(
      `https://api.linkedin.com/rest/organizationalEntityShareStatistics?q=organizationalEntity&organizationalEntity=${encodedUrn}`,
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchOrganizationPosts(accessToken, organizationUrn, options = {}) {
  try {
    const encodedUrn = encodeURIComponent(organizationUrn);
    const count = Number(options.count) > 0 ? Number(options.count) : 10;
    const start = Number(options.start) >= 0 ? Number(options.start) : 0;
    const viewContext = options.viewContext || "AUTHOR";
    const response = await axios.get(
      `https://api.linkedin.com/rest/posts?author=${encodedUrn}&q=author&count=${count}&start=${start}&sortBy=LAST_MODIFIED&viewContext=${viewContext}`,
      {
        headers: {
          ...getRestHeaders(accessToken),
          "X-RestLi-Method": "FINDER",
        },
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function fetchPostSocialActions(accessToken, postUrn) {
  try {
    const encodedUrn = encodeURIComponent(postUrn);
    const response = await axios.get(
      `https://api.linkedin.com/rest/socialActions/${encodedUrn}`,
      {
        headers: getRestHeaders(accessToken),
      }
    );

    return { ok: true, status: response.status, data: response.data };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

function extractFollowerCount(followerCountResult) {
  if (!followerCountResult?.ok) {
    return null;
  }

  return followerCountResult.data?.firstDegreeSize ?? null;
}

function formatDisplayDate(value) {
  if (!value) {
    return "Unknown";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Unknown";
  }

  return parsed.toLocaleString();
}

function updateFollowerHistory(results) {
  if (!results?.organizations?.length) {
    return;
  }

  tokenStore.followerHistory = tokenStore.followerHistory || {};
  const capturedAt = new Date().toISOString();

  for (const organization of results.organizations) {
    if (
      !organization.organizationId ||
      organization.followerCount === null ||
      organization.followerCount === undefined
    ) {
      continue;
    }

    const existingHistory = tokenStore.followerHistory[organization.organizationId] || [];
    const lastSnapshot = existingHistory[existingHistory.length - 1];

    if (lastSnapshot?.count === organization.followerCount) {
      lastSnapshot.capturedAt = capturedAt;
      continue;
    }

    existingHistory.push({
      capturedAt,
      count: organization.followerCount,
    });

    tokenStore.followerHistory[organization.organizationId] = existingHistory.slice(-30);
  }
}

function getFollowerHistory(organizationId) {
  return tokenStore.followerHistory?.[organizationId] || [];
}

function extractFollowerDemographics(followerDemographicsResult) {
  if (!followerDemographicsResult?.ok) {
    return null;
  }

  return followerDemographicsResult.data?.elements?.[0] || null;
}

function extractPageStatistics(pageStatisticsResult) {
  if (!pageStatisticsResult?.ok) {
    return null;
  }

  return pageStatisticsResult.data?.elements?.[0] || null;
}

function extractShareStatistics(shareStatisticsResult) {
  if (!shareStatisticsResult?.ok) {
    return null;
  }

  return shareStatisticsResult.data?.elements?.[0]?.totalShareStatistics || null;
}

function extractPublishedPosts(organizationPostsResult) {
  if (!organizationPostsResult?.ok) {
    return [];
  }

  return (organizationPostsResult.data?.elements || []).filter(
    (post) => post?.lifecycleState === "PUBLISHED"
  );
}

function extractPostAnalytics(socialActionsResult) {
  if (!socialActionsResult?.ok) {
    return {
      likes: null,
      comments: null,
      engagements: null,
      views: null,
    };
  }

  const data = socialActionsResult.data || {};
  const likes =
    data.likesSummary?.aggregatedTotalLikes ??
    data.likesSummary?.totalLikes ??
    data.numLikes ??
    data.likeCount ??
    null;
  const comments =
    data.commentsSummary?.aggregatedTotalComments ??
    data.commentsSummary?.totalFirstLevelComments ??
    data.commentsSummary?.count ??
    data.numComments ??
    data.commentCount ??
    null;
  const views =
    data.impressions ??
    data.impressionCount ??
    data.views ??
    data.viewCount ??
    null;
  const engagements =
    data.engagement ??
    data.engagementCount ??
    (likes !== null || comments !== null
      ? (likes || 0) + (comments || 0)
      : null);

  return {
    likes,
    comments,
    engagements,
    views,
  };
}

async function enrichPostsWithAnalytics(accessToken, posts) {
  const enrichedPosts = [];

  for (const post of posts) {
    const socialActionsResult = post?.id
      ? await fetchPostSocialActions(accessToken, post.id)
      : null;
    const analytics = extractPostAnalytics(socialActionsResult);

    enrichedPosts.push({
      ...post,
      socialActionsResult,
      analytics,
    });
  }

  return enrichedPosts;
}

function formatFacetLabel(value) {
  if (!value && value !== 0) {
    return "Unknown";
  }

  const normalized = String(value);
  const urnParts = normalized.split(":");
  const urnType = urnParts.length > 2 ? urnParts[2] : null;
  const urnSegment = normalized.includes(":")
    ? urnParts[urnParts.length - 1]
    : normalized;

  const functionLabels = {
    "4": "Business Development",
    "8": "Engineering",
    "10": "Finance",
    "13": "Information Technology",
    "18": "Operations",
    "25": "Sales",
  };

  const seniorityLabels = {
    "1": "Unpaid",
    "2": "Training",
    "3": "Entry",
    "4": "Senior",
    "5": "Manager",
    "6": "Director",
    "7": "VP",
    "8": "CXO",
    "9": "Owner",
    "10": "Partner",
  };

  const industryLabels = {
    "4": "Computer Software",
    "11": "Management Consulting",
    "46": "Financial Services",
    "57": "Human Resources",
    "96": "Information Technology & Services",
    "901": "Online Media",
  };

  const geoLabels = {
    "101165590": "United Kingdom",
    "100459316": "India",
    "102713980": "France",
    "103644278": "United States",
    "104305776": "Germany",
    "105015875": "United Arab Emirates",
  };

  if (urnType === "function") {
    return functionLabels[urnSegment] || `Function ${urnSegment}`;
  }

  if (urnType === "seniority") {
    return seniorityLabels[urnSegment] || `Seniority ${urnSegment}`;
  }

  if (urnType === "industry") {
    return industryLabels[urnSegment] || `Industry ${urnSegment}`;
  }

  if (urnType === "geo") {
    return geoLabels[urnSegment] || `Geo ${urnSegment}`;
  }

  return urnSegment
    .replace(/_/g, " ")
    .replace(/-/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

async function createOrganizationPost(accessToken, organizationUrn, options = {}) {
  const commentary = options.commentary || "Test draft post from local LinkedIn API utility.";
  const lifecycleState = options.lifecycleState || "DRAFT";
  const payload = {
    author: organizationUrn,
    commentary,
    visibility: "PUBLIC",
    distribution: {
      feedDistribution: "MAIN_FEED",
      targetEntities: [],
      thirdPartyDistributionChannels: [],
    },
    lifecycleState,
    isReshareDisabledByAuthor: false,
  };

  try {
    const response = await axios.post(
      "https://api.linkedin.com/rest/posts",
      payload,
      {
        headers: {
          ...getRestHeaders(accessToken),
          "Content-Type": "application/json",
        },
      }
    );

    return {
      ok: true,
      status: response.status,
      data: response.data,
      note:
        lifecycleState === "PUBLISHED"
          ? "Organization post published."
          : "Draft post request attempted.",
    };
  } catch (error) {
    return { ok: false, error: normalizeError(error) };
  }
}

async function enrichOrganization(accessToken, organization, options = {}) {
  if (!organization.organizationId) {
    return organization;
  }

  const detailsResult = await fetchOrganizationDetails(
    accessToken,
    organization.organizationId
  );
  const followerCountResult = await fetchOrganizationFollowerCount(
    accessToken,
    organization.organizationUrn
  );
  const followerDemographicsResult = await fetchOrganizationFollowerDemographics(
    accessToken,
    organization.organizationUrn
  );
  const followerDemographics = extractFollowerDemographics(
    followerDemographicsResult
  );
  const pageStatisticsResult = await fetchOrganizationPageStatistics(
    accessToken,
    organization.organizationUrn
  );
  const shareStatisticsResult = await fetchOrganizationShareStatistics(
    accessToken,
    organization.organizationUrn
  );
  const pageStatistics = extractPageStatistics(pageStatisticsResult);
  const shareStatistics = extractShareStatistics(shareStatisticsResult);
  const organizationPostsResult = options.includePosts
    ? await fetchOrganizationPosts(accessToken, organization.organizationUrn, {
        count: options.postCount || 10,
      })
    : organization.organizationPostsResult || null;
  const publishedPosts = options.includePosts
    ? await enrichPostsWithAnalytics(
        accessToken,
        extractPublishedPosts(organizationPostsResult)
      )
    : organization.publishedPosts || [];

  return {
    ...organization,
    detailsResult,
    followerCountResult,
    followerDemographicsResult,
    followerDemographics,
    pageStatisticsResult,
    pageStatistics,
    shareStatisticsResult,
    shareStatistics,
    organizationPostsResult,
    publishedPosts,
    name: detailsResult.ok
      ? detailsResult.data?.localizedName ||
        detailsResult.data?.name?.localized?.en_US ||
        detailsResult.data?.name ||
        null
      : organization.name || null,
    vanityName: detailsResult.ok
      ? detailsResult.data?.vanityName || null
      : organization.vanityName || null,
    organizationType: detailsResult.ok
      ? detailsResult.data?.organizationType || null
      : organization.organizationType || null,
    followerCount: extractFollowerCount(followerCountResult),
    description: detailsResult.ok
      ? detailsResult.data?.description?.localized?.en_US ||
        detailsResult.data?.description ||
        null
      : organization.description || null,
  };
}

function summarizeCapabilities(grantedScopes) {
  const capabilities = [];

  if (
    grantedScopes.includes("openid") ||
    grantedScopes.includes("profile") ||
    grantedScopes.includes("email")
  ) {
    capabilities.push(
      "Can test OIDC identity endpoints for your own account."
    );
  }

  if (grantedScopes.includes("r_liteprofile")) {
    capabilities.push("Can test the legacy lite profile endpoint.");
  }

  if (grantedScopes.includes("r_emailaddress")) {
    capabilities.push("Can test the legacy email address endpoint.");
  }

  if (grantedScopes.includes("rw_organization_admin")) {
    capabilities.push("Can inspect organizations you administer.");
  }

  if (grantedScopes.includes("r_organization_social")) {
    capabilities.push("Can attempt organization social read operations.");
  }

  if (grantedScopes.includes("w_organization_social")) {
    capabilities.push("Can attempt organization post creation.");
  }

  if (!capabilities.length) {
    capabilities.push(
      "No recognized member or organization scopes were granted."
    );
  }

  capabilities.push(
    "Self-serve LinkedIn app access does not expose your connections list or detailed data about your connections."
  );

  return capabilities;
}

function buildCapabilityStatus(label, ok, detail) {
  return {
    label,
    ok,
    detail,
  };
}

function deriveAccessStatus(results) {
  const organizations = results?.organizations || [];
  const approvedOrganizations = organizations.filter(
    (organization) => organization.state === "APPROVED"
  );
  const anyOrganization = approvedOrganizations[0] || organizations[0] || null;
  const anyPublishedPost =
    anyOrganization?.publishedPosts?.find((post) => post?.id) || null;

  const statusItems = [
    buildCapabilityStatus(
      "Organization ACL discovery",
      Boolean(results?.organizationAclResult?.ok),
      results?.organizationAclResult?.ok
        ? `${organizations.length} organizations visible to this token.`
        : results?.organizationAclResult?.error?.data?.message ||
            results?.organizationAclResult?.note ||
            "LinkedIn did not return organization ACLs."
    ),
    buildCapabilityStatus(
      "Organization profile lookup",
      Boolean(anyOrganization?.detailsResult?.ok),
      anyOrganization?.detailsResult?.ok
        ? `Organization details are readable for ${getOrganizationDisplayName(anyOrganization)}.`
        : anyOrganization?.detailsResult?.error?.data?.message ||
            "Organization profile fields are not currently readable."
    ),
    buildCapabilityStatus(
      "Page follower count",
      Boolean(anyOrganization?.followerCountResult?.ok),
      anyOrganization?.followerCountResult?.ok
        ? "LinkedIn returned page follower totals."
        : anyOrganization?.followerCountResult?.error?.data?.message ||
            "Page follower totals are blocked or unavailable."
    ),
    buildCapabilityStatus(
      "Page visitor analytics",
      Boolean(anyOrganization?.pageStatisticsResult?.ok),
      anyOrganization?.pageStatisticsResult?.ok
        ? "LinkedIn returned aggregate page visitor analytics."
        : anyOrganization?.pageStatisticsResult?.error?.data?.message ||
            "Aggregate page visitor analytics are blocked or unavailable."
    ),
    buildCapabilityStatus(
      "Organization post list",
      Boolean(anyOrganization?.organizationPostsResult?.ok),
      anyOrganization?.organizationPostsResult?.ok
        ? `LinkedIn returned ${anyOrganization?.publishedPosts?.length || 0} published posts for the sampled page.`
        : anyOrganization?.organizationPostsResult?.error?.data?.message ||
            "Organization posts could not be retrieved."
    ),
    buildCapabilityStatus(
      "Create organization posts",
      results?.grantedScopes?.includes("w_organization_social"),
      results?.grantedScopes?.includes("w_organization_social")
        ? "This token can attempt page post creation for approved organizations."
        : "The token is missing w_organization_social."
    ),
    buildCapabilityStatus(
      "Per-post social analytics",
      Boolean(anyPublishedPost?.socialActionsResult?.ok),
      anyPublishedPost?.socialActionsResult?.ok
        ? "LinkedIn returned post-level social analytics."
        : anyPublishedPost?.socialActionsResult?.error?.data?.message ||
            "Per-post analytics have not been returned for the sampled post."
    ),
  ];

  return {
    sampledOrganizationName: anyOrganization
      ? getOrganizationDisplayName(anyOrganization)
      : null,
    sampledPostId: anyPublishedPost?.id || null,
    items: statusItems,
  };
}

function extractOrganizations(organizationAclResult) {
  const elements = organizationAclResult?.data?.elements || [];

  return elements.map((entry) => ({
    state: entry.state,
    role: entry.role,
    roleAssignee: entry.roleAssignee || null,
    createdBy: entry.created?.actor || null,
    lastModifiedBy: entry.lastModified?.actor || null,
    organizationUrn: entry.organization,
    organizationId: String(entry.organization || "").split(":").pop() || null,
  }));
}

function extractAuthenticatedMemberUrn(organizations) {
  const firstOrganization = organizations.find((organization) => organization.roleAssignee);
  return firstOrganization?.roleAssignee || null;
}

async function enrichOrganizations(accessToken, organizations, options = {}) {
  const enrichedOrganizations = [];

  for (const organization of organizations) {
    enrichedOrganizations.push(
      await enrichOrganization(accessToken, organization, options)
    );
  }

  return enrichedOrganizations;
}

function organizationNeedsRefresh(organization, options = {}) {
  const postAnalyticsMissing =
    options.includePosts &&
    Array.isArray(organization?.publishedPosts) &&
    organization.publishedPosts.some(
      (post) =>
        !Object.prototype.hasOwnProperty.call(post, "socialActionsResult") ||
        !Object.prototype.hasOwnProperty.call(post, "analytics")
    );

  return (
    !organization ||
    !Object.prototype.hasOwnProperty.call(organization, "followerCount") ||
    !organization.followerCountResult ||
    !organization.detailsResult ||
    !Object.prototype.hasOwnProperty.call(organization, "followerDemographicsResult") ||
    !Object.prototype.hasOwnProperty.call(organization, "pageStatisticsResult") ||
    !Object.prototype.hasOwnProperty.call(organization, "shareStatisticsResult") ||
    (options.includePosts &&
      (!Object.prototype.hasOwnProperty.call(organization, "organizationPostsResult") ||
        postAnalyticsMissing))
  );
}

function getSessionSnapshot() {
  const cachedOrganizations = tokenStore.lastResults?.organizations || [];

  return {
    appLoginConfigured: isAppLoginConfigured(),
    isAuthenticated: Boolean(tokenStore.accessToken),
    grantedScopes: tokenStore.grantedScopes,
    tokenMeta: {
      expiresIn: tokenStore.tokenResponse?.expires_in || null,
      savedAt: tokenStore.savedAt,
    },
    authenticatedMemberUrn: extractAuthenticatedMemberUrn(cachedOrganizations),
    requestedScopes: scopes,
    hasCachedResults: Boolean(tokenStore.lastResults),
    organizations: cachedOrganizations.length
      ? cachedOrganizations
      : extractOrganizations(tokenStore.lastResults?.organizationAclResult),
  };
}

async function runLinkedInTests(accessToken, options = {}) {
  const grantedScopes = tokenStore.grantedScopes;

  const memberProfileResult =
    grantedScopes.includes("openid") ||
    grantedScopes.includes("profile") ||
    grantedScopes.includes("email")
      ? await fetchUserInfo(accessToken)
      : makeSkippedResult(
          "OIDC member profile test skipped. Requires openid/profile/email scopes and the Sign In with LinkedIn product."
        );

  const liteProfileResult = grantedScopes.includes("r_liteprofile")
    ? await fetchLiteProfile(accessToken)
    : makeSkippedResult(
        "Legacy lite profile test skipped. Requires r_liteprofile."
      );

  const emailAddressResult = grantedScopes.includes("r_emailaddress")
    ? await fetchEmailAddress(accessToken)
    : makeSkippedResult(
        "Legacy email test skipped. Requires r_emailaddress."
      );

  const organizationAclResult = grantedScopes.includes("rw_organization_admin")
    ? await fetchOrganizationAcls(accessToken)
    : makeSkippedResult(
        "Organization ACL test skipped. Requires rw_organization_admin."
      );

  let organizationPostResult = makeSkippedResult(
    "Post test skipped. Select an approved organization button to try a draft post."
  );

  if (options.createPost && options.organizationUrn) {
    const postResult = await createOrganizationPost(
      accessToken,
      options.organizationUrn,
      {
        commentary: buildDraftTestCommentary(options.organizationUrn),
        lifecycleState: "DRAFT",
      }
    );

    organizationPostResult = {
      attempted: true,
      organizationUrn: options.organizationUrn,
      ...postResult,
    };
  } else if (options.createPost) {
    organizationPostResult = {
      attempted: true,
      ok: false,
      error: {
        message:
          "Missing organizationUrn query parameter. Example: urn:li:organization:123456",
        status: 400,
        statusText: "Bad Request",
        data: null,
      },
    };
  }

  const organizations = extractOrganizations(organizationAclResult);
  const enrichedOrganizations = await enrichOrganizations(accessToken, organizations);

  return {
    tokenReceived: Boolean(accessToken),
    grantedScopes,
    capabilitySummary: summarizeCapabilities(grantedScopes),
    limitations: [
      "Connections list and detailed connection data are not exposed through the normal self-serve LinkedIn member API flow used by this app.",
      "Your current scopes do not include member profile access, so the app can identify the authenticated member only by LinkedIn member URN, not by person name.",
    ],
    authenticatedMemberUrn: extractAuthenticatedMemberUrn(organizations),
    memberProfileResult,
    liteProfileResult,
    emailAddressResult,
    organizationAclResult,
    organizationPostResult,
    organizations: enrichedOrganizations,
  };
}

function renderHomePage({ flashMessage = "" } = {}) {
  const session = getSessionSnapshot();
  const initialResults = tokenStore.lastResults;
  const accessStatus = deriveAccessStatus(initialResults);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LinkedIn Capability Explorer</title>
    <style>
      :root {
        --bg: #f4efe7;
        --panel: rgba(255, 250, 244, 0.86);
        --panel-strong: #fff8f0;
        --text: #172033;
        --muted: #5f697d;
        --brand: #0a66c2;
        --brand-dark: #084d93;
        --accent: #ff875a;
        --success: #107c41;
        --warning: #9a5a00;
        --danger: #b42318;
        --border: rgba(23, 32, 51, 0.1);
        --shadow: 0 24px 60px rgba(25, 30, 45, 0.14);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Georgia, "Times New Roman", serif;
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(255, 135, 90, 0.28), transparent 30%),
          radial-gradient(circle at top right, rgba(10, 102, 194, 0.25), transparent 32%),
          linear-gradient(160deg, #fbf6ef 0%, #efe5d8 48%, #f7efe4 100%);
      }
      .shell {
        width: min(1180px, calc(100% - 32px));
        margin: 24px auto 40px;
      }
      .hero {
        background: linear-gradient(135deg, rgba(255, 248, 240, 0.96), rgba(255, 241, 229, 0.82));
        border: 1px solid rgba(255, 255, 255, 0.7);
        border-radius: 28px;
        box-shadow: var(--shadow);
        overflow: hidden;
      }
      .hero-inner {
        display: grid;
        grid-template-columns: 1.35fr .95fr;
        gap: 24px;
        padding: 28px;
      }
      .kicker {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 8px 12px;
        border-radius: 999px;
        background: rgba(10, 102, 194, 0.1);
        color: var(--brand-dark);
        font-size: 13px;
        letter-spacing: .08em;
        text-transform: uppercase;
      }
      h1 {
        margin: 18px 0 14px;
        font-size: clamp(34px, 5vw, 64px);
        line-height: .96;
        letter-spacing: -0.04em;
      }
      .lead {
        margin: 0;
        max-width: 58ch;
        color: var(--muted);
        font-size: 18px;
        line-height: 1.6;
      }
      .hero-side {
        background: rgba(255,255,255,.58);
        border: 1px solid rgba(255,255,255,.75);
        border-radius: 22px;
        padding: 20px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
      }
      .hero-side h2, .panel h2 {
        margin: 0 0 12px;
        font-size: 18px;
      }
      .mini-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
      }
      .stat {
        padding: 14px;
        border-radius: 18px;
        background: rgba(255,255,255,.7);
        border: 1px solid var(--border);
      }
      .stat-label {
        font-size: 12px;
        letter-spacing: .08em;
        text-transform: uppercase;
        color: var(--muted);
      }
      .stat-value {
        margin-top: 8px;
        font-size: 22px;
        font-weight: 700;
      }
      .grid {
        display: grid;
        grid-template-columns: 1.05fr .95fr;
        gap: 20px;
        margin-top: 20px;
      }
      .panel {
        background: var(--panel);
        border: 1px solid rgba(255,255,255,0.72);
        border-radius: 24px;
        box-shadow: var(--shadow);
        padding: 22px;
      }
      .panel p {
        margin: 0;
        color: var(--muted);
      }
      .badge-row, .button-row, .org-row {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
      }
      .badge {
        display: inline-flex;
        align-items: center;
        padding: 8px 12px;
        border-radius: 999px;
        background: rgba(23, 32, 51, 0.07);
        border: 1px solid rgba(23, 32, 51, 0.07);
        color: var(--text);
        font-size: 14px;
      }
      .button-row {
        margin-top: 18px;
      }
      .inline-form {
        margin: 0;
      }
      button, .link-button {
        border: 0;
        border-radius: 16px;
        padding: 12px 16px;
        font: inherit;
        cursor: pointer;
        transition: transform .16s ease, box-shadow .16s ease, background .16s ease;
        text-decoration: none;
      }
      button:hover, .link-button:hover {
        transform: translateY(-1px);
      }
      .primary {
        background: linear-gradient(135deg, var(--brand), #39a1ff);
        color: white;
        box-shadow: 0 10px 24px rgba(10, 102, 194, 0.28);
      }
      .secondary {
        background: rgba(255,255,255,.74);
        color: var(--text);
        border: 1px solid var(--border);
      }
      .warm {
        background: linear-gradient(135deg, #f48c68, var(--accent));
        color: white;
        box-shadow: 0 10px 24px rgba(255, 135, 90, 0.28);
      }
      .status {
        margin-top: 16px;
        padding: 14px 16px;
        border-radius: 18px;
        font-size: 14px;
      }
      .status.info {
        background: rgba(10, 102, 194, 0.1);
        color: var(--brand-dark);
      }
      .status.warn {
        background: rgba(154, 90, 0, 0.12);
        color: var(--warning);
      }
      .status.ok {
        background: rgba(16, 124, 65, 0.12);
        color: var(--success);
      }
      .result-card {
        margin-top: 18px;
        background: var(--panel-strong);
        border: 1px solid var(--border);
        border-radius: 20px;
        overflow: hidden;
      }
      .result-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
        padding: 14px 16px;
        border-bottom: 1px solid var(--border);
      }
      .result-head strong {
        font-size: 15px;
      }
      .result-body {
        padding: 16px;
      }
      .result-summary-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 12px;
      }
      .result-stat {
        padding: 14px;
        border-radius: 18px;
        background: rgba(255,255,255,.8);
        border: 1px solid var(--border);
      }
      .result-stat-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: var(--muted);
      }
      .result-stat-value {
        margin-top: 8px;
        font-size: 24px;
        font-weight: 700;
      }
      .viz-list {
        display: grid;
        gap: 12px;
        margin-top: 16px;
      }
      .viz-item {
        padding: 14px;
        border-radius: 18px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.76);
      }
      .viz-top {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: baseline;
      }
      .viz-title {
        font-size: 18px;
        font-weight: 700;
      }
      .viz-subtitle {
        margin-top: 6px;
        color: var(--muted);
        font-size: 14px;
      }
      .viz-bar {
        height: 10px;
        margin-top: 12px;
        border-radius: 999px;
        background: rgba(23, 32, 51, 0.08);
        overflow: hidden;
      }
      .viz-fill {
        height: 100%;
        border-radius: 999px;
        background: linear-gradient(135deg, var(--brand), #39a1ff);
      }
      .viz-fill.zero {
        background: linear-gradient(135deg, #c4cbd8, #a2acbd);
      }
      .viz-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 12px;
      }
      details.result-raw {
        border-top: 1px solid var(--border);
        padding: 0 16px 16px;
      }
      details.result-raw summary {
        cursor: pointer;
        padding-top: 14px;
        font-weight: 700;
      }
      .chip {
        padding: 6px 10px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 700;
      }
      .chip.ok { background: rgba(16,124,65,.12); color: var(--success); }
      .chip.warn { background: rgba(154,90,0,.14); color: var(--warning); }
      .chip.fail { background: rgba(180,35,24,.12); color: var(--danger); }
      pre {
        margin: 0;
        padding: 16px;
        max-height: 520px;
        overflow: auto;
        background: #1f2430;
        color: #eff4ff;
        font-size: 13px;
        line-height: 1.5;
      }
      .org-list {
        display: grid;
        gap: 12px;
        margin-top: 18px;
      }
      .org-item {
        padding: 14px;
        border-radius: 18px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.72);
      }
      .composer {
        margin-top: 14px;
      }
      .composer-input {
        width: 100%;
        min-height: 132px;
        margin-top: 8px;
        padding: 14px 16px;
        border-radius: 18px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.95);
        color: var(--text);
        font: inherit;
        line-height: 1.5;
        resize: vertical;
      }
      .composer-input:focus {
        outline: 2px solid rgba(10, 102, 194, 0.18);
        border-color: rgba(10, 102, 194, 0.32);
      }
      .org-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 10px;
      }
      .footer-note {
        margin-top: 20px;
        color: var(--muted);
        font-size: 14px;
      }
      .inline-link {
        color: var(--brand-dark);
        text-decoration: none;
        font-weight: 700;
      }
      .access-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
        margin-top: 18px;
      }
      .access-card {
        padding: 14px;
        border-radius: 18px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.72);
      }
      .access-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
      }
      .access-detail {
        margin-top: 10px;
        color: var(--muted);
        font-size: 14px;
        line-height: 1.5;
      }
      @media (max-width: 960px) {
        .hero-inner, .grid, .result-summary-grid, .access-grid {
          grid-template-columns: 1fr;
        }
      }
      @media (max-width: 640px) {
        .shell {
          width: min(100% - 20px, 100%);
          margin-top: 12px;
        }
        .hero-inner, .panel {
          padding: 18px;
        }
        .mini-grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <section class="hero">
        <div class="hero-inner">
          <div>
            <div class="kicker">LinkedIn Capability Explorer</div>
            <h1>Probe what your app can actually do.</h1>
            <p class="lead">This dashboard keeps your access token locally, lets you re-run LinkedIn checks without raw callback URLs, and turns the current scope set into one-click tests for member and organization functionality.</p>
            <div class="button-row">
              <a class="link-button primary" href="/auth/linkedin">${session.isAuthenticated ? "Reconnect LinkedIn" : "Login with LinkedIn"}</a>
              <button class="secondary" id="refreshAllButton">Run Full Check</button>
              <button class="secondary" id="refreshSessionButton">Refresh Session</button>
              <button class="warm" id="logoutButton">Forget Saved Token</button>
              <form class="inline-form" method="post" action="/app/logout">
                <button class="secondary" type="submit">App Logout</button>
              </form>
            </div>
            ${
              flashMessage
                ? `<div class="status ok">${flashMessage}</div>`
                : ""
            }
            ${
              getMissingEnvVars().length
                ? `<div class="status warn">Missing environment variables: ${getMissingEnvVars().join(", ")}</div>`
                : ""
            }
          </div>
          <aside class="hero-side">
            <h2>Session</h2>
            <div class="mini-grid">
              <div class="stat">
                <div class="stat-label">Auth Status</div>
                <div class="stat-value">${session.isAuthenticated ? "Saved" : "Missing"}</div>
              </div>
              <div class="stat">
                <div class="stat-label">Granted Scopes</div>
                <div class="stat-value">${session.grantedScopes.length}</div>
              </div>
              <div class="stat">
                <div class="stat-label">Saved At</div>
                <div class="stat-value">${session.tokenMeta.savedAt ? "Present" : "None"}</div>
              </div>
              <div class="stat">
                <div class="stat-label">Organizations</div>
                <div class="stat-value">${session.organizations.length}</div>
              </div>
            </div>
            <p class="footer-note">Requested scopes: ${scopes.join(", ")}</p>
            <p class="footer-note">Authenticated member URN: ${session.authenticatedMemberUrn || "Not resolved yet"}</p>
          </aside>
        </div>
      </section>

      <section class="grid">
        <div class="panel">
          <h2>Scope Map</h2>
          <p>These are the scopes requested by the current <code>.env</code> configuration. LinkedIn may grant fewer.</p>
          <div class="badge-row" style="margin-top:16px">
            ${scopes.map((scope) => `<span class="badge">${scope}</span>`).join("")}
          </div>
          <h2 style="margin-top:22px">LinkedIn Access Status</h2>
          <p>This panel summarizes what the current saved token and app access are actually allowing right now.</p>
          ${
            accessStatus.sampledOrganizationName
              ? `<div class="footer-note">Sampled page: ${accessStatus.sampledOrganizationName}${accessStatus.sampledPostId ? ` · Sampled post: ${accessStatus.sampledPostId}` : ""}</div>`
              : `<div class="footer-note">No organization sample is available yet. Run the full check after logging in.</div>`
          }
          <div class="access-grid">
            ${accessStatus.items
              .map(
                (item) => `
                  <div class="access-card">
                    <div class="access-top">
                      <strong>${item.label}</strong>
                      <span class="chip ${item.ok ? "ok" : "fail"}">${item.ok ? "Allowed" : "Blocked"}</span>
                    </div>
                    <div class="access-detail">${escapeHtml(item.detail)}</div>
                  </div>
                `
              )
              .join("")}
          </div>
          <h2 style="margin-top:22px">Function Tests</h2>
          <p>Each button runs one isolated probe so you can tell which path is available without scanning a full callback payload.</p>
          <div class="button-row">
            <button class="secondary test-button" data-endpoint="/api/test/member">Test OIDC Member</button>
            <button class="secondary test-button" data-endpoint="/api/test/lite-profile">Test Lite Profile</button>
            <button class="secondary test-button" data-endpoint="/api/test/email">Test Email</button>
            <button class="secondary test-button" data-endpoint="/api/test/org-acls">Test Org ACLs</button>
          </div>
          <div class="status info" style="margin-top:18px">Connections data is not available through the normal self-serve LinkedIn API flow used by this app.</div>
          <div id="result"></div>
        </div>

        <div class="panel">
          <h2>Organizations</h2>
          <p>Approved organizations can now publish text posts directly from this dashboard. Draft testing is still available for quick permission checks.</p>
          <div class="org-list" id="orgList"></div>
        </div>
      </section>
    </div>

    <script>
      const initialSession = ${safeJsonForHtml(session)};
      const initialResults = ${safeJsonForHtml(initialResults)};

      const resultRoot = document.getElementById("result");
      const orgListRoot = document.getElementById("orgList");

      function renderResult(title, payload) {
        const state = payload?.ok === false || payload?.error ? "fail" : payload?.attempted === false ? "warn" : "ok";
        const label = state === "ok" ? "Success" : state === "warn" ? "Skipped" : "Error";
        const visual = renderPayloadVisualization(title, payload);
        resultRoot.innerHTML = \`
          <div class="result-card">
            <div class="result-head">
              <strong>\${title}</strong>
              <span class="chip \${state}">\${label}</span>
            </div>
            \${visual}
          </div>
        \`;
      }

      function escapeHtml(value) {
        return value
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;");
      }

      function formatDate(value) {
        if (!value) {
          return "Unknown";
        }

        const parsed = new Date(Number(value));
        if (Number.isNaN(parsed.getTime())) {
          return "Unknown";
        }

        return parsed.toLocaleString();
      }

      function renderPayloadVisualization(title, payload) {
        if (payload?.organizations && Array.isArray(payload.organizations)) {
          return renderOrganizationMetricsVisualization(title, payload);
        }

        const linkedinMessage = payload?.error?.data?.message;
        const inputErrorMessage = payload?.error?.data?.errorDetails?.inputErrors
          ?.map((item) => item.description)
          .filter(Boolean)
          .join("; ");
        const duplicateNotice = payload?.error?.data?.errorDetails?.inputErrors
          ?.some((item) => item.code === "DUPLICATE_POST")
          ? '<div class="status warn">LinkedIn rejected this because the post content matches a recent post for that page. Change the text and try again.</div>'
          : "";
        const summary = linkedinMessage || inputErrorMessage
          ? \`<div class="status warn">\${escapeHtml(linkedinMessage || inputErrorMessage)}</div>\`
          : "";

        return \`\${duplicateNotice}\${summary}<pre>\${escapeHtml(JSON.stringify(payload, null, 2))}</pre>\`;
      }

      function renderOrganizationMetricsVisualization(title, payload) {
        const organizations = payload.organizations || [];
        const approvedCount = organizations.filter((org) => org.state === "APPROVED").length;
        const rejectedCount = organizations.filter((org) => org.state === "REJECTED").length;
        const visibleFollowerCounts = organizations
          .map((org) => org.followerCount)
          .filter((count) => count !== null && count !== undefined);
        const totalFollowers = visibleFollowerCounts.reduce((sum, count) => sum + count, 0);
        const topFollowerCount = Math.max(...visibleFollowerCounts, 0);

        const cards = organizations.map((org) => {
          const width = topFollowerCount > 0 && org.followerCount !== null && org.followerCount !== undefined
            ? Math.max((org.followerCount / topFollowerCount) * 100, 2)
            : 0;
          const followerLabel = org.followerCount !== null && org.followerCount !== undefined
            ? org.followerCount.toLocaleString()
            : "Unavailable";
          const detailsState = org.detailsResult?.ok
            ? "Organization Lookup OK"
            : "Organization Lookup " + (org.detailsResult?.error?.status || "Unavailable");

          return \`
            <div class="viz-item">
              <div class="viz-top">
                <div>
                  <div class="viz-title">\${escapeHtml(org.name || org.organizationUrn)}</div>
                  <div class="viz-subtitle">Org ID \${escapeHtml(org.organizationId || "Unknown")} · ACL \${escapeHtml(org.state || "Unknown")}</div>
                </div>
                <a class="inline-link" href="/organizations/\${encodeURIComponent(org.organizationId)}">Open</a>
              </div>
              <div class="viz-bar">
                <div class="viz-fill \${width === 0 ? "zero" : ""}" style="width:\${width}%"></div>
              </div>
              <div class="viz-meta">
                <span class="badge">Followers: \${followerLabel}</span>
                <span class="badge">Role: \${escapeHtml(org.role || "Unknown")}</span>
                \${org.organizationType ? '<span class="badge">Type: ' + escapeHtml(org.organizationType) + '</span>' : ""}
                \${org.vanityName ? '<span class="badge">Vanity: ' + escapeHtml(org.vanityName) + '</span>' : ""}
                <span class="badge">\${escapeHtml(detailsState)}</span>
                <span class="badge">Last ACL Update: \${escapeHtml(formatDate(org.lastModifiedBy ? payload.data?.elements?.find((item) => item.organization === org.organizationUrn)?.lastModified?.time : null))}</span>
              </div>
            </div>
          \`;
        }).join("");

        return \`
          <div class="result-body">
            <div class="result-summary-grid">
              <div class="result-stat">
                <div class="result-stat-label">Organizations</div>
                <div class="result-stat-value">\${organizations.length}</div>
              </div>
              <div class="result-stat">
                <div class="result-stat-label">Approved</div>
                <div class="result-stat-value">\${approvedCount}</div>
              </div>
              <div class="result-stat">
                <div class="result-stat-label">Rejected</div>
                <div class="result-stat-value">\${rejectedCount}</div>
              </div>
              <div class="result-stat">
                <div class="result-stat-label">Visible Followers</div>
                <div class="result-stat-value">\${totalFollowers.toLocaleString()}</div>
              </div>
            </div>
            <div class="viz-list">\${cards}</div>
          </div>
          <details class="result-raw">
            <summary>Show Raw JSON</summary>
            <pre>\${escapeHtml(JSON.stringify(payload, null, 2))}</pre>
          </details>
        \`;
      }

      function renderOrganizations(results) {
        const orgs = results?.organizations || initialSession.organizations || [];

        if (!orgs.length) {
          orgListRoot.innerHTML = '<div class="status warn">No cached organization results yet. Run "Test Org ACLs" or "Run Full Check" after logging in.</div>';
          return;
        }

        orgListRoot.innerHTML = orgs.map((org) => {
          const approved = org.state === "APPROVED";
          const typeBadge = org.organizationType
            ? '<span class="badge">Type: ' + org.organizationType + '</span>'
            : "";
          const vanityBadge = org.vanityName
            ? '<span class="badge">Vanity: ' + org.vanityName + '</span>'
            : "";
          const assigneeBlock = org.roleAssignee
            ? '<div class="footer-note">Authenticated member URN on ACL: ' + org.roleAssignee + '</div>'
            : "";
          const followerBadge = org.followerCount !== null && org.followerCount !== undefined
            ? '<span class="badge">Page Followers: ' + org.followerCount + '</span>'
            : "";
          const composerMarkup = approved
            ? \`
              <div class="composer">
                <label class="footer-note" for="post-text-\${org.organizationId || org.organizationUrn}">Post text</label>
                <textarea
                  id="post-text-\${org.organizationId || org.organizationUrn}"
                  class="composer-input"
                  data-post-text-for="\${org.organizationUrn}"
                  maxlength="3000"
                  placeholder="Write the LinkedIn page post text here..."
                ></textarea>
                <div class="button-row">
                  <button class="warm org-publish-button" data-urn="\${org.organizationUrn}">Publish Post</button>
                  <button class="secondary org-draft-button" data-urn="\${org.organizationUrn}">Save Draft Test</button>
                </div>
              </div>
            \`
            : '<div class="status warn" style="margin-top:12px">Publishing is disabled because this page is not APPROVED for the current token.</div>';
          return \`
            <div class="org-item">
              <strong>\${org.name || org.organizationUrn}</strong>
              <div class="footer-note" style="margin-top:8px">URN: \${org.organizationUrn}</div>
              <div class="org-meta">
                <span class="badge">State: \${org.state}</span>
                <span class="badge">Role: \${org.role || "Unknown"}</span>
                <span class="badge">ID: \${org.organizationId || "Unknown"}</span>
                \${followerBadge}
                \${typeBadge}
                \${vanityBadge}
              </div>
              \${assigneeBlock}
              \${composerMarkup}
              <div class="button-row">
                <a class="link-button secondary" href="/organizations/\${org.organizationId}">View More</a>
              </div>
            </div>
          \`;
        }).join("");

        document.querySelectorAll(".org-publish-button").forEach((button) => {
          button.addEventListener("click", async () => {
            const urn = button.getAttribute("data-urn");
            const input = document.querySelector('[data-post-text-for="' + urn + '"]');
            const payload = await callApi("/api/posts", "POST", {
              organizationUrn: urn,
              commentary: input ? input.value : "",
              lifecycleState: "PUBLISHED",
            });
            renderResult("Organization Post Publish", payload);
          });
        });

        document.querySelectorAll(".org-draft-button").forEach((button) => {
          button.addEventListener("click", async () => {
            const urn = button.getAttribute("data-urn");
            const input = document.querySelector('[data-post-text-for="' + urn + '"]');
            const payload = await callApi("/api/posts", "POST", {
              organizationUrn: urn,
              commentary: input ? input.value : "",
              lifecycleState: "DRAFT",
            });
            renderResult("Organization Draft Post", payload);
          });
        });
      }

      async function callApi(endpoint, method = "GET", body) {
        const response = await fetch(endpoint, {
          method,
          headers: body ? { "Content-Type": "application/json" } : undefined,
          body: body ? JSON.stringify(body) : undefined,
        });
        const payload = await response.json();
        return payload;
      }

      async function runAllChecks() {
        const payload = await callApi("/api/test/all");
        renderResult("Full Capability Check", payload);
        renderOrganizations(payload);
      }

      document.querySelectorAll(".test-button").forEach((button) => {
        button.addEventListener("click", async () => {
          const payload = await callApi(button.getAttribute("data-endpoint"));
          renderResult(button.textContent, payload);
          if (payload.organizations) {
            renderOrganizations(payload);
          }
        });
      });

      document.getElementById("refreshAllButton").addEventListener("click", runAllChecks);

      document.getElementById("refreshSessionButton").addEventListener("click", async () => {
        const payload = await callApi("/api/session");
        renderResult("Current Session", payload);
      });

      document.getElementById("logoutButton").addEventListener("click", async () => {
        const payload = await callApi("/api/logout", "POST");
        renderResult("Saved Token Removed", payload);
        setTimeout(() => window.location.reload(), 500);
      });

      if (initialResults) {
        renderOrganizations(initialResults);
      } else {
        renderOrganizations(null);
      }
    </script>
  </body>
</html>`;
}

function renderLoginPage({ errorMessage = "" } = {}) {
  const configError = getAppLoginConfigError();

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LinkedIn Buddy Login</title>
    <style>
      :root {
        --bg: #f4efe7;
        --panel: rgba(255, 250, 244, 0.92);
        --text: #172033;
        --muted: #5f697d;
        --brand: #0a66c2;
        --brand-dark: #084d93;
        --danger: #b42318;
        --border: rgba(23, 32, 51, 0.12);
        --shadow: 0 24px 60px rgba(25, 30, 45, 0.14);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
        font-family: Georgia, "Times New Roman", serif;
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(255, 135, 90, 0.24), transparent 30%),
          radial-gradient(circle at top right, rgba(10, 102, 194, 0.22), transparent 32%),
          linear-gradient(160deg, #fbf6ef 0%, #efe5d8 48%, #f7efe4 100%);
      }
      .card {
        width: min(460px, 100%);
        padding: 30px;
        border-radius: 28px;
        background: var(--panel);
        border: 1px solid rgba(255, 255, 255, 0.74);
        box-shadow: var(--shadow);
      }
      .eyebrow {
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--brand);
      }
      h1 {
        margin: 12px 0 10px;
        font-size: clamp(32px, 7vw, 42px);
        line-height: 1.05;
      }
      p {
        margin: 0;
        color: var(--muted);
        line-height: 1.6;
      }
      form {
        display: grid;
        gap: 14px;
        margin-top: 24px;
      }
      label {
        display: grid;
        gap: 8px;
        font-size: 14px;
        font-weight: 700;
      }
      input {
        width: 100%;
        padding: 14px 16px;
        border-radius: 16px;
        border: 1px solid var(--border);
        font: inherit;
      }
      button {
        margin-top: 6px;
        border: 0;
        border-radius: 999px;
        padding: 14px 18px;
        font: inherit;
        font-weight: 700;
        color: white;
        background: linear-gradient(135deg, var(--brand), var(--brand-dark));
        cursor: pointer;
      }
      .notice {
        margin-top: 16px;
        padding: 14px 16px;
        border-radius: 18px;
        background: rgba(180, 35, 24, 0.08);
        color: var(--danger);
      }
    </style>
  </head>
  <body>
    <section class="card">
      <div class="eyebrow">Protected Access</div>
      <h1>LinkedIn Buddy</h1>
      <p>Sign in to access the dashboard and LinkedIn OAuth tools for this deployment.</p>
      ${configError ? `<div class="notice">${escapeHtml(configError)}</div>` : ""}
      ${errorMessage ? `<div class="notice">${escapeHtml(errorMessage)}</div>` : ""}
      <form method="post" action="/login">
        <label>
          Username
          <input type="text" name="username" autocomplete="username" required />
        </label>
        <label>
          Password
          <input type="password" name="password" autocomplete="current-password" required />
        </label>
        <button type="submit">Open Dashboard</button>
      </form>
    </section>
  </body>
</html>`;
}

function requireToken(res) {
  if (!tokenStore.accessToken) {
    res.status(401).json({
      tokenReceived: false,
      error: "No saved access token. Use the Login with LinkedIn button first.",
    });
    return false;
  }

  return true;
}

function requireAppLogin(req, res, next) {
  if (req.path === "/login" || req.path === "/health") {
    return next();
  }

  const session = readAppSession(req);
  if (session.ok) {
    req.appSession = session;
    return next();
  }

  clearAppSessionCookie(res);

  if (isBrowserRequest(req)) {
    return res.redirect("/login");
  }

  return res.status(401).json({
    ok: false,
    error: session.error || "App login required.",
  });
}

async function runAndPersistTests(options = {}) {
  const results = await runLinkedInTests(tokenStore.accessToken, options);
  tokenStore.lastResults = results;
  updateFollowerHistory(results);
  persistTokenStore();
  return results;
}

async function loadOrganizationForRequest(organizationId) {
  if (!tokenStore.lastResults?.organizations?.length) {
    await runAndPersistTests();
  }

  let organization = (tokenStore.lastResults?.organizations || []).find(
    (item) => item.organizationId === organizationId
  );

  if (!organization) {
    await runAndPersistTests();
    organization = (tokenStore.lastResults?.organizations || []).find(
      (item) => item.organizationId === organizationId
    );
  }

  if (!organization) {
    return null;
  }

  if (organizationNeedsRefresh(organization, { includePosts: true })) {
    organization = await enrichOrganization(tokenStore.accessToken, organization, {
      includePosts: true,
      postCount: 10,
    });

    if (tokenStore.lastResults?.organizations?.length) {
      tokenStore.lastResults.organizations = tokenStore.lastResults.organizations.map(
        (item) => (item.organizationId === organizationId ? organization : item)
      );
      persistTokenStore();
    }
  }

  return organization;
}

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(requireAppLogin);

app.get("/login", (req, res) => {
  const session = readAppSession(req);
  if (session.ok) {
    return res.redirect("/");
  }

  const errorParam = req.query.error;
  const errorMap = {
    invalid_credentials: "Invalid username or password.",
  };

  res.send(renderLoginPage({ errorMessage: errorMap[errorParam] || "" }));
});

app.post("/login", (req, res) => {
  if (!isAppLoginConfigured()) {
    return res.status(500).send(renderLoginPage({ errorMessage: getAppLoginConfigError() }));
  }

  const submittedUsername = String(req.body?.username || "").trim();
  const submittedPassword = String(req.body?.password || "");

  if (
    submittedUsername !== appLoginUsername ||
    submittedPassword !== appLoginPassword
  ) {
    return res.redirect("/login?error=invalid_credentials");
  }

  setAppSessionCookie(res, submittedUsername);
  return res.redirect("/");
});

app.post("/app/logout", (req, res) => {
  clearAppSessionCookie(res);
  res.redirect("/login");
});

app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    appLoginConfigured: isAppLoginConfigured(),
  });
});

app.get("/", (req, res) => {
  const flashParam = req.query.flash;
  const flashMap = {
    login_success: "LinkedIn token saved locally. You can now re-run tests without logging in again.",
    callback_reused: "That callback URL was already consumed. Use the dashboard buttons or /api/test routes instead.",
  };

  res.send(renderHomePage({ flashMessage: flashMap[flashParam] || "" }));
});

function renderOrganizationPage(organization) {
  const name = organization.name || organization.organizationUrn;
  const followerValue = organization.followerCount ?? "Unavailable";
  const canPublish = organization.state === "APPROVED";
  const publishedPosts = organization.publishedPosts || [];
  const postsStatusLabel = organization.organizationPostsResult?.ok
    ? `Published posts fetched: ${publishedPosts.length}`
    : `Post listing unavailable${
        organization.organizationPostsResult?.error?.status
          ? ` (${organization.organizationPostsResult.error.status})`
          : ""
      }`;
  const followerMarkup =
    organization.followerCount !== null && organization.followerCount !== undefined
      ? `<a class="value-link" href="/organizations/${organization.organizationId}/followers">${organization.followerCount}</a>`
      : `<span class="value-link disabled">${followerValue}</span>`;
  const publishedPostsMarkup = publishedPosts.length
    ? publishedPosts
        .map((post) => {
          const commentary = post.commentary?.trim() || "No commentary returned.";
          const publishedAt = post.publishedAt || post.createdAt || post.lastModifiedAt || null;
          const analytics = post.analytics || {};
          const likesLabel = analytics.likes ?? "Unavailable";
          const commentsLabel = analytics.comments ?? "Unavailable";
          const engagementsLabel = analytics.engagements ?? "Unavailable";
          const viewsLabel = analytics.views ?? "Unavailable";
          const analyticsStatus = post.socialActionsResult?.ok
            ? "Post analytics fetched"
            : (post.socialActionsResult?.error?.data?.message ||
                `Post analytics unavailable${
                  post.socialActionsResult?.error?.status
                    ? ` (${post.socialActionsResult.error.status})`
                    : ""
                }`);
          return `
            <article class="post-card">
              <div class="post-meta">
                <span class="chip">State: ${escapeHtml(post.lifecycleState || "Unknown")}</span>
                <span class="chip">Published: ${escapeHtml(formatDisplayDate(publishedAt))}</span>
                <span class="chip">ID: ${escapeHtml(post.id || "Unknown")}</span>
              </div>
              <div class="post-meta" style="margin-top:10px">
                <span class="chip">Views: ${escapeHtml(String(viewsLabel))}</span>
                <span class="chip">Likes: ${escapeHtml(String(likesLabel))}</span>
                <span class="chip">Comments: ${escapeHtml(String(commentsLabel))}</span>
                <span class="chip">Engagements: ${escapeHtml(String(engagementsLabel))}</span>
              </div>
              <p class="post-body">${escapeHtml(commentary)}</p>
              <p class="muted" style="margin:12px 0 0">${escapeHtml(analyticsStatus)}</p>
            </article>
          `;
        })
        .join("")
    : `<div class="status">No published posts were returned for this page yet.</div>`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${name} | LinkedIn Capability Explorer</title>
    <style>
      :root {
        --bg: #f4efe7;
        --panel: rgba(255, 250, 244, 0.9);
        --text: #172033;
        --muted: #5f697d;
        --brand: #0a66c2;
        --accent: #ff875a;
        --success: #107c41;
        --warning: #9a5a00;
        --border: rgba(23, 32, 51, 0.1);
        --shadow: 0 24px 60px rgba(25, 30, 45, 0.14);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Georgia, "Times New Roman", serif;
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(255, 135, 90, 0.28), transparent 30%),
          radial-gradient(circle at top right, rgba(10, 102, 194, 0.25), transparent 32%),
          linear-gradient(160deg, #fbf6ef 0%, #efe5d8 48%, #f7efe4 100%);
      }
      .shell {
        width: min(1120px, calc(100% - 32px));
        margin: 24px auto 40px;
      }
      .panel {
        background: var(--panel);
        border: 1px solid rgba(255,255,255,0.72);
        border-radius: 24px;
        box-shadow: var(--shadow);
        padding: 24px;
      }
      .topbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 16px;
        margin-bottom: 20px;
      }
      .back {
        text-decoration: none;
        color: white;
        background: linear-gradient(135deg, var(--brand), #39a1ff);
        padding: 12px 16px;
        border-radius: 16px;
        font-weight: 700;
      }
      h1 {
        margin: 14px 0 10px;
        font-size: clamp(32px, 5vw, 56px);
        line-height: .98;
      }
      .lead {
        margin: 0;
        color: var(--muted);
        font-size: 18px;
        line-height: 1.6;
      }
      .grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 14px;
        margin-top: 22px;
      }
      .stat {
        background: rgba(255,255,255,.74);
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 16px;
      }
      .label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: var(--muted);
      }
      .value {
        margin-top: 8px;
        font-size: 24px;
        font-weight: 700;
      }
      .value-link {
        margin-top: 8px;
        display: inline-block;
        font-size: 24px;
        font-weight: 700;
        color: var(--brand);
        text-decoration: none;
        border-bottom: 2px solid rgba(10, 102, 194, 0.22);
      }
      .value-link.disabled {
        color: var(--text);
        border-bottom: 0;
        pointer-events: none;
      }
      .value-link:hover {
        color: var(--brand);
      }
      .content-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        margin-top: 20px;
      }
      .section {
        background: rgba(255,255,255,.72);
        border: 1px solid var(--border);
        border-radius: 22px;
        padding: 20px;
      }
      .section h2 {
        margin: 0 0 12px;
        font-size: 20px;
      }
      .chips {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
      }
      .chip {
        padding: 8px 12px;
        border-radius: 999px;
        background: rgba(23, 32, 51, 0.07);
        border: 1px solid rgba(23, 32, 51, 0.08);
        font-size: 14px;
      }
      details {
        margin-top: 14px;
      }
      summary {
        cursor: pointer;
        font-weight: 700;
      }
      pre {
        margin: 12px 0 0;
        padding: 16px;
        border-radius: 18px;
        background: #1f2430;
        color: #eff4ff;
        overflow: auto;
        max-height: 520px;
        font-size: 13px;
        line-height: 1.5;
      }
      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 18px;
      }
      .composer {
        margin-top: 18px;
      }
      .composer-input {
        width: 100%;
        min-height: 180px;
        margin-top: 10px;
        padding: 14px 16px;
        border-radius: 18px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.95);
        color: var(--text);
        font: inherit;
        line-height: 1.5;
        resize: vertical;
      }
      .composer-input:focus {
        outline: 2px solid rgba(10, 102, 194, 0.18);
        border-color: rgba(10, 102, 194, 0.32);
      }
      .button {
        text-decoration: none;
        border: 0;
        border-radius: 16px;
        padding: 12px 16px;
        font: inherit;
        cursor: pointer;
      }
      .button.warm {
        color: white;
        background: linear-gradient(135deg, #f48c68, var(--accent));
      }
      .button.light {
        background: rgba(255,255,255,.74);
        color: var(--text);
        border: 1px solid var(--border);
      }
      .post-list {
        display: grid;
        gap: 14px;
        margin-top: 16px;
      }
      .post-card {
        padding: 16px;
        border-radius: 18px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.78);
      }
      .post-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .post-body {
        margin: 12px 0 0;
        white-space: pre-wrap;
        line-height: 1.6;
      }
      .status {
        margin-top: 16px;
        padding: 14px 16px;
        border-radius: 18px;
        background: rgba(23, 32, 51, 0.06);
      }
      .muted {
        color: var(--muted);
      }
      @media (max-width: 920px) {
        .grid, .content-grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="topbar">
        <a class="back" href="/">Back to Landing Page</a>
      </div>
      <section class="panel">
        <div class="label">Organization Detail</div>
        <h1>${name}</h1>
        <p class="lead">This page shows the organization fields and metrics your current token can actually read. Page follower count is fetched from LinkedIn's documented network size endpoint. Post likes and comments require specific post URNs, so they are not aggregated here unless the app later enumerates posts.</p>
        <div class="grid">
          <div class="stat">
            <div class="label">Organization ID</div>
            <div class="value">${organization.organizationId || "Unknown"}</div>
          </div>
          <div class="stat">
            <div class="label">Page Followers</div>
            <div class="value">${followerMarkup}</div>
          </div>
          <div class="stat">
            <div class="label">ACL State</div>
            <div class="value">${organization.state || "Unknown"}</div>
          </div>
          <div class="stat">
            <div class="label">Role</div>
            <div class="value">${organization.role || "Unknown"}</div>
          </div>
        </div>
        <div class="content-grid">
          <section class="section">
            <h2>Available Data</h2>
            <div class="chips">
              <span class="chip">URN: ${organization.organizationUrn}</span>
              ${organization.vanityName ? `<span class="chip">Vanity: ${organization.vanityName}</span>` : ""}
              ${organization.organizationType ? `<span class="chip">Type: ${organization.organizationType}</span>` : ""}
              ${organization.detailsResult?.ok ? `<span class="chip">Organization Lookup: OK</span>` : `<span class="chip">Organization Lookup: ${organization.detailsResult?.error?.status || "Unavailable"}</span>`}
              ${organization.followerCountResult?.ok ? `<span class="chip">Page Followers: OK</span>` : `<span class="chip">Page Followers: ${organization.followerCountResult?.error?.status || "Unavailable"}</span>`}
            </div>
            ${organization.description ? `<details open><summary>View More</summary><p class="muted">${organization.description}</p></details>` : `<p class="muted">No organization description was returned.</p>`}
            ${
              canPublish
                ? `
            <div class="composer">
              <label class="muted" for="organizationPostText">Write page post</label>
              <textarea id="organizationPostText" class="composer-input" maxlength="3000" placeholder="Write the LinkedIn page post text here..."></textarea>
              <div class="actions">
                <button class="button warm" id="publishPostButton">Publish Post</button>
                <button class="button light" id="saveDraftButton">Save Draft</button>
              </div>
            </div>`
                : `<div class="status" style="margin-top:16px">Publishing is disabled because this organization is not APPROVED for the current token.</div>`
            }
            <div class="actions">
              <a class="button warm" href="/api/test/create-post?organizationUrn=${encodeURIComponent(organization.organizationUrn)}">Test Draft Post</a>
              <a class="button light" href="/">Back</a>
            </div>
          </section>
          <section class="section">
            <h2>Metrics Notes</h2>
            <p class="muted">Currently available here:</p>
            <div class="chips">
              <span class="chip">Page follower count</span>
              <span class="chip">ACL role and state</span>
              <span class="chip">Organization profile fields</span>
            </div>
            <p class="muted" style="margin-top:14px">Potentially available with more implementation and the right product access:</p>
            <div class="chips">
              <span class="chip">Post-level likes</span>
              <span class="chip">Post-level comments</span>
              <span class="chip">Post social summaries</span>
            </div>
            <p class="muted" style="margin-top:14px">Those post social metrics use LinkedIn's documented <code>socialActions</code> endpoints, but they require post URNs rather than just the organization URN.</p>
          </section>
        </div>
        <section class="section" style="margin-top:20px">
          <h2>Published Posts</h2>
          <div class="chips">
            <span class="chip">${postsStatusLabel}</span>
            <span class="chip">Showing up to 10 most recently modified posts</span>
          </div>
          ${
            organization.organizationPostsResult?.ok
              ? `<div class="post-list">${publishedPostsMarkup}</div>`
              : `<div class="status">LinkedIn did not return posts for this page. ${
                  organization.organizationPostsResult?.error?.data?.message ||
                  organization.organizationPostsResult?.error?.message ||
                  "Review your token scopes and page access."
                }</div>`
          }
        </section>
        <section class="section" style="margin-top:20px">
          <h2>Raw Organization Payload</h2>
          <pre>${safeJsonForHtml(organization)}</pre>
        </section>
      </section>
    </div>
    <script>
      const organizationUrn = ${safeJsonForHtml(organization.organizationUrn)};
      const postInput = document.getElementById("organizationPostText");
      const publishButton = document.getElementById("publishPostButton");
      const draftButton = document.getElementById("saveDraftButton");

      async function submitOrganizationPost(lifecycleState) {
        if (!postInput) {
          return;
        }

        const response = await fetch("/api/posts", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            organizationUrn,
            commentary: postInput.value,
            lifecycleState,
          }),
        });

        const payload = await response.json();
        const message = payload?.ok
          ? (lifecycleState === "PUBLISHED" ? "Post published successfully." : "Draft saved successfully.")
          : (payload?.error?.data?.message || payload?.error?.message || "LinkedIn rejected the post.");

        window.alert(message);

        if (payload?.ok && lifecycleState === "PUBLISHED") {
          window.location.reload();
        }
      }

      if (publishButton) {
        publishButton.addEventListener("click", () => submitOrganizationPost("PUBLISHED"));
      }

      if (draftButton) {
        draftButton.addEventListener("click", () => submitOrganizationPost("DRAFT"));
      }
    </script>
  </body>
</html>`;
}

function renderFollowerDetailsPage(organization) {
  const name = organization.name || organization.organizationUrn;
  const followerPayload = safeJsonForHtml(organization.followerCountResult || null);
  const demographicsPayload = safeJsonForHtml(
    organization.followerDemographicsResult || null
  );
  const pageStatisticsPayload = safeJsonForHtml(
    organization.pageStatisticsResult || null
  );
  const shareStatisticsPayload = safeJsonForHtml(
    organization.shareStatisticsResult || null
  );
  const hasFollowerCount =
    organization.followerCount !== null && organization.followerCount !== undefined;
  const demographics = organization.followerDemographics || null;
  const pageStatistics = organization.pageStatistics || null;
  const shareStatistics = organization.shareStatistics || null;
  const history = getFollowerHistory(organization.organizationId);
  const latestSnapshot = history[history.length - 1] || null;
  const previousSnapshot = history.length > 1 ? history[history.length - 2] : null;
  const firstSnapshot = history[0] || null;
  const delta = latestSnapshot && previousSnapshot
    ? latestSnapshot.count - previousSnapshot.count
    : null;
  const historyMax = history.length
    ? Math.max(...history.map((item) => item.count), 1)
    : 1;
  const historyMarkup = history.length
    ? history
        .slice()
        .reverse()
        .map((item) => {
          const width = Math.max((item.count / historyMax) * 100, item.count > 0 ? 4 : 0);
          return `
            <div class="history-row">
              <div>
                <div class="history-count">${item.count.toLocaleString()} followers</div>
                <div class="history-date">${formatDisplayDate(item.capturedAt)}</div>
              </div>
              <div class="history-bar">
                <div class="history-fill ${item.count === 0 ? "zero" : ""}" style="width:${width}%"></div>
              </div>
            </div>
          `;
        })
        .join("")
    : '<p class="muted">No follower history yet. Use "Run Full Check" or "Test Org ACLs" over time to build trend data.</p>';
  const deltaLabel =
    delta === null
      ? "N/A"
      : `${delta > 0 ? "+" : ""}${delta.toLocaleString()}`;
  const facetConfigs = [
    ["followerCountsByGeoCountry", "Top Countries", "geo"],
    ["followerCountsByFunction", "Top Functions", "function"],
    ["followerCountsByIndustry", "Top Industries", "industry"],
    ["followerCountsBySeniority", "Top Seniority", "seniority"],
    ["followerCountsByStaffCountRange", "Company Sizes", "staffCountRange"],
    ["followerCountsByAssociationType", "Association Type", "associationType"],
  ];
  const demographicSections = demographics
    ? facetConfigs
        .map(([facetKey, title, valueKey]) => {
          const rows = (demographics[facetKey] || [])
            .map((item) => ({
              label: formatFacetLabel(item[valueKey]),
              count: item.followerCounts?.organicFollowerCount ?? 0,
            }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 6);

          if (!rows.length) {
            return "";
          }

          return `
            <section class="section">
              <h2>${title}</h2>
              <div class="demo-list">
                ${rows
                  .map((row) => {
                    const width = hasFollowerCount && organization.followerCount > 0
                      ? Math.max((row.count / organization.followerCount) * 100, row.count > 0 ? 3 : 0)
                      : 0;

                    return `
                      <div class="demo-row">
                        <div class="demo-top">
                          <strong>${row.label}</strong>
                          <span>${row.count.toLocaleString()}</span>
                        </div>
                        <div class="demo-bar">
                          <div class="demo-fill" style="width:${width}%"></div>
                        </div>
                      </div>
                    `;
                  })
                  .join("")}
              </div>
            </section>
          `;
        })
        .filter(Boolean)
        .join("")
    : "";
  const visitorFacetConfigs = [
    ["pageStatisticsByIndustryV2", "Top Visitor Industries", "industryV2"],
    ["pageStatisticsByFunction", "Top Visitor Functions", "function"],
    ["pageStatisticsBySeniority", "Top Visitor Seniority", "seniority"],
    ["pageStatisticsByGeo", "Top Visitor Regions", "geo"],
  ];
  const visitorSectionData = visitorFacetConfigs
    .map(([facetKey, title, valueKey]) => {
      const rows = ((pageStatistics && pageStatistics[facetKey]) || [])
        .map((item) => ({
          label: formatFacetLabel(item[valueKey]),
          totalViews: item.pageStatistics?.views?.allPageViews?.pageViews ?? 0,
          overviewViews: item.pageStatistics?.views?.overviewPageViews?.pageViews ?? 0,
          aboutViews: item.pageStatistics?.views?.aboutPageViews?.pageViews ?? 0,
          jobsViews: item.pageStatistics?.views?.jobsPageViews?.pageViews ?? 0,
          peopleViews: item.pageStatistics?.views?.peoplePageViews?.pageViews ?? 0,
          careersViews: item.pageStatistics?.views?.careersPageViews?.pageViews ?? 0,
        }))
        .sort((a, b) => b.totalViews - a.totalViews)
        .slice(0, 6);

      return { title, rows };
    })
    .filter((section) => section.rows.length);
  const visitorBaseRows =
    visitorSectionData.find((section) => section.title === "Top Visitor Seniority")?.rows ||
    visitorSectionData[0]?.rows ||
    [];
  const totalVisitorViews = visitorBaseRows.reduce((sum, row) => sum + row.totalViews, 0);
  const totalOverviewViews = visitorBaseRows.reduce((sum, row) => sum + row.overviewViews, 0);
  const totalAboutViews = visitorBaseRows.reduce((sum, row) => sum + row.aboutViews, 0);
  const totalPeopleViews = visitorBaseRows.reduce((sum, row) => sum + row.peopleViews, 0);
  const totalJobsViews = visitorBaseRows.reduce((sum, row) => sum + row.jobsViews, 0);
  const totalCareersViews = visitorBaseRows.reduce((sum, row) => sum + row.careersViews, 0);
  const visitorSectionsMarkup = visitorSectionData
    .map((section) => {
      const sectionMax = Math.max(...section.rows.map((row) => row.totalViews), 1);
      return `
        <section class="section">
          <h2>${section.title}</h2>
          <div class="demo-list">
            ${section.rows
              .map((row) => {
                const width = Math.max((row.totalViews / sectionMax) * 100, row.totalViews > 0 ? 3 : 0);

                return `
                  <div class="demo-row">
                    <div class="demo-top">
                      <strong>${row.label}</strong>
                      <span>${row.totalViews.toLocaleString()} views</span>
                    </div>
                    <div class="demo-bar">
                      <div class="demo-fill" style="width:${width}%"></div>
                    </div>
                    <div class="chips" style="margin-top:10px">
                      <span class="chip">Overview: ${row.overviewViews.toLocaleString()}</span>
                      <span class="chip">About: ${row.aboutViews.toLocaleString()}</span>
                      <span class="chip">People: ${row.peopleViews.toLocaleString()}</span>
                      <span class="chip">Jobs: ${row.jobsViews.toLocaleString()}</span>
                      <span class="chip">Careers: ${row.careersViews.toLocaleString()}</span>
                    </div>
                  </div>
                `;
              })
              .join("")}
          </div>
        </section>
      `;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${name} Followers | LinkedIn Capability Explorer</title>
    <style>
      :root {
        --bg: #f4efe7;
        --panel: rgba(255, 250, 244, 0.9);
        --text: #172033;
        --muted: #5f697d;
        --brand: #0a66c2;
        --success: #107c41;
        --warning: #9a5a00;
        --border: rgba(23, 32, 51, 0.1);
        --shadow: 0 24px 60px rgba(25, 30, 45, 0.14);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: Georgia, "Times New Roman", serif;
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(255, 135, 90, 0.28), transparent 30%),
          radial-gradient(circle at top right, rgba(10, 102, 194, 0.25), transparent 32%),
          linear-gradient(160deg, #fbf6ef 0%, #efe5d8 48%, #f7efe4 100%);
      }
      .shell {
        width: min(1120px, calc(100% - 32px));
        margin: 24px auto 40px;
      }
      .panel {
        background: var(--panel);
        border: 1px solid rgba(255,255,255,0.72);
        border-radius: 24px;
        box-shadow: var(--shadow);
        padding: 24px;
      }
      .topbar, .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: center;
      }
      .topbar {
        justify-content: space-between;
        margin-bottom: 20px;
      }
      .back, .button {
        text-decoration: none;
        color: white;
        background: linear-gradient(135deg, var(--brand), #39a1ff);
        padding: 12px 16px;
        border-radius: 16px;
        font-weight: 700;
      }
      .button.light {
        color: var(--text);
        background: rgba(255,255,255,.74);
        border: 1px solid var(--border);
      }
      .tabs {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin: 18px 0 6px;
      }
      .tab {
        display: inline-flex;
        align-items: center;
        padding: 10px 14px;
        border-radius: 999px;
        text-decoration: none;
        font-weight: 700;
        border: 1px solid var(--border);
        background: rgba(255,255,255,.74);
        color: var(--text);
      }
      .tab.active {
        background: linear-gradient(135deg, var(--brand), #39a1ff);
        color: white;
        border-color: transparent;
      }
      h1 {
        margin: 14px 0 10px;
        font-size: clamp(32px, 5vw, 56px);
        line-height: .98;
      }
      .lead, .muted {
        color: var(--muted);
      }
      .lead {
        margin: 0;
        font-size: 18px;
        line-height: 1.6;
      }
      .grid, .content-grid {
        display: grid;
        gap: 18px;
      }
      .grid {
        grid-template-columns: repeat(3, minmax(0, 1fr));
        margin-top: 22px;
      }
      .content-grid {
        grid-template-columns: 1.05fr .95fr;
        margin-top: 20px;
      }
      .stat, .section {
        background: rgba(255,255,255,.74);
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 18px;
      }
      .label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: var(--muted);
      }
      .value {
        margin-top: 8px;
        font-size: 28px;
        font-weight: 700;
      }
      .section h2 {
        margin: 0 0 12px;
        font-size: 20px;
      }
      .chips {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
      }
      .chip {
        padding: 8px 12px;
        border-radius: 999px;
        background: rgba(23, 32, 51, 0.07);
        border: 1px solid rgba(23, 32, 51, 0.08);
        font-size: 14px;
      }
      .status {
        margin-top: 14px;
        padding: 14px 16px;
        border-radius: 18px;
        font-size: 15px;
        background: rgba(154, 90, 0, 0.12);
        color: var(--warning);
      }
      .status.good {
        background: rgba(16, 124, 65, 0.12);
        color: var(--success);
      }
      .history-list {
        display: grid;
        gap: 12px;
        margin-top: 16px;
      }
      .history-row {
        display: grid;
        grid-template-columns: 220px 1fr;
        gap: 14px;
        align-items: center;
        padding: 14px;
        border-radius: 18px;
        background: rgba(255,255,255,.74);
        border: 1px solid var(--border);
      }
      .history-count {
        font-size: 18px;
        font-weight: 700;
      }
      .history-date {
        margin-top: 4px;
        color: var(--muted);
        font-size: 14px;
      }
      .history-bar {
        height: 12px;
        border-radius: 999px;
        background: rgba(23, 32, 51, 0.08);
        overflow: hidden;
      }
      .history-fill {
        height: 100%;
        border-radius: 999px;
        background: linear-gradient(135deg, var(--brand), #39a1ff);
      }
      .history-fill.zero {
        background: linear-gradient(135deg, #c4cbd8, #a2acbd);
      }
      .demo-list {
        display: grid;
        gap: 12px;
        margin-top: 14px;
      }
      .demo-row {
        padding: 12px 14px;
        border-radius: 18px;
        background: rgba(255,255,255,.74);
        border: 1px solid var(--border);
      }
      .demo-top {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
      }
      .demo-bar {
        height: 10px;
        margin-top: 10px;
        border-radius: 999px;
        background: rgba(23, 32, 51, 0.08);
        overflow: hidden;
      }
      .demo-fill {
        height: 100%;
        border-radius: 999px;
        background: linear-gradient(135deg, var(--brand), #39a1ff);
      }
      details {
        margin-top: 16px;
      }
      summary {
        cursor: pointer;
        font-weight: 700;
      }
      .tab-panel {
        display: none;
      }
      .tab-panel.active {
        display: block;
      }
      pre {
        margin: 12px 0 0;
        padding: 16px;
        border-radius: 18px;
        background: #1f2430;
        color: #eff4ff;
        overflow: auto;
        max-height: 520px;
        font-size: 13px;
        line-height: 1.5;
      }
      @media (max-width: 920px) {
        .grid, .content-grid {
          grid-template-columns: 1fr;
        }
        .history-row {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="topbar">
        <a class="back" href="/organizations/${organization.organizationId}">Back to Organization</a>
      </div>
      <section class="panel">
        <div class="label">Follower Details</div>
        <h1>${name}</h1>
        <p class="lead">This audience view shows what your current LinkedIn token can retrieve for this page. Followers and visitors are both aggregate analytics only; LinkedIn does not return a browsable member list for either.</p>
        <div class="tabs">
          <a class="tab active" href="#followers" data-tab="followers">Followers</a>
          <a class="tab" href="#visitors" data-tab="visitors">Visitors</a>
        </div>
        <div class="tab-panel active" data-panel="followers">
        <div class="grid">
          <div class="stat">
            <div class="label">Page Followers</div>
            <div class="value">${hasFollowerCount ? organization.followerCount : "Unavailable"}</div>
          </div>
          <div class="stat">
            <div class="label">Previous Snapshot</div>
            <div class="value">${previousSnapshot ? previousSnapshot.count.toLocaleString() : "N/A"}</div>
          </div>
          <div class="stat">
            <div class="label">Change Since Last</div>
            <div class="value">${deltaLabel}</div>
          </div>
          <div class="stat">
            <div class="label">First Recorded</div>
            <div class="value">${firstSnapshot ? firstSnapshot.count.toLocaleString() : "N/A"}</div>
          </div>
          <div class="stat">
            <div class="label">Demographic Facets</div>
            <div class="value">${demographics ? Object.keys(demographics).filter((key) => key.startsWith("followerCountsBy") && Array.isArray(demographics[key]) && demographics[key].length).length : 0}</div>
          </div>
        </div>
        <div class="content-grid">
          <section class="section">
            <h2>Follower Trend</h2>
            <div class="chips">
              <span class="chip">Total follower count</span>
              <span class="chip">Snapshot history</span>
              <span class="chip">Delta over time</span>
            </div>
            <div class="status ${delta !== null && delta >= 0 ? "good" : ""}">${previousSnapshot ? `Latest change: ${deltaLabel} followers since ${formatDisplayDate(previousSnapshot.capturedAt)}.` : "Only one snapshot is stored so far. Refresh org metrics again later to build a trend line."}</div>
            <div class="history-list">${historyMarkup}</div>
            <div class="actions" style="margin-top:18px">
              <a class="button" href="/api/test/org-acls">Capture New Snapshot</a>
              <a class="button light" href="/organizations/${organization.organizationId}">Back</a>
            </div>
          </section>
          <section class="section">
            <h2>What This Means</h2>
            <div class="chips">
              <span class="chip">URN: ${organization.organizationUrn}</span>
              <span class="chip">ID: ${organization.organizationId || "Unknown"}</span>
              <span class="chip">ACL State: ${organization.state || "Unknown"}</span>
              <span class="chip">Role: ${organization.role || "Unknown"}</span>
              ${organization.followerDemographicsResult?.ok ? '<span class="chip">Demographics: OK</span>' : `<span class="chip">Demographics: ${organization.followerDemographicsResult?.error?.status || "Unavailable"}</span>`}
            </div>
            <p class="muted" style="margin-top:14px">LinkedIn is currently giving this app one follower metric only: <code>firstDegreeSize</code>. That means we can track how your page audience changes over time, but not who the followers are.</p>
            <div class="status">Member-level follower identities, profile names, headlines, companies, and locations are not present in this response. The demographic breakdowns are aggregate buckets, not a people list.</div>
            <p class="muted" style="margin-top:14px">Last captured: ${latestSnapshot ? formatDisplayDate(latestSnapshot.capturedAt) : "Not captured yet"}.</p>
          </section>
        </div>
        ${demographicSections ? `<div class="content-grid" style="margin-top:20px">${demographicSections}</div>` : `<section class="section" style="margin-top:20px"><h2>Follower Demographics</h2><p class="muted">No demographic follower segments were returned for this page yet. Use "Capture New Snapshot" to retry, or confirm your page/token has access to organization follower statistics.</p></section>`}
        <section class="section" style="margin-top:20px">
          <h2>Raw Follower Metric Payload</h2>
          <pre>${followerPayload}</pre>
        </section>
        <section class="section" style="margin-top:20px">
          <h2>Raw Demographics Payload</h2>
          <details>
            <summary>Show demographics JSON</summary>
            <pre>${demographicsPayload}</pre>
          </details>
        </section>
        </div>
        <div class="tab-panel" data-panel="visitors">
          <div class="grid">
            <div class="stat">
              <div class="label">Visitor Views</div>
              <div class="value">${totalVisitorViews ? totalVisitorViews.toLocaleString() : "Unavailable"}</div>
            </div>
            <div class="stat">
              <div class="label">Overview Views</div>
              <div class="value">${totalOverviewViews.toLocaleString()}</div>
            </div>
            <div class="stat">
              <div class="label">About Views</div>
              <div class="value">${totalAboutViews.toLocaleString()}</div>
            </div>
            <div class="stat">
              <div class="label">People Views</div>
              <div class="value">${totalPeopleViews.toLocaleString()}</div>
            </div>
            <div class="stat">
              <div class="label">Jobs Views</div>
              <div class="value">${totalJobsViews.toLocaleString()}</div>
            </div>
            <div class="stat">
              <div class="label">Careers Views</div>
              <div class="value">${totalCareersViews.toLocaleString()}</div>
            </div>
            <div class="stat">
              <div class="label">Post Impressions</div>
              <div class="value">${shareStatistics?.impressionCount?.toLocaleString?.() || "Unavailable"}</div>
            </div>
            <div class="stat">
              <div class="label">Unique Impressions</div>
              <div class="value">${shareStatistics?.uniqueImpressionsCount?.toLocaleString?.() || "Unavailable"}</div>
            </div>
          </div>
          <div class="content-grid">
            <section class="section">
              <h2>Visitor Analytics</h2>
              <div class="chips">
                <span class="chip">Views by industry</span>
                <span class="chip">Views by function</span>
                <span class="chip">Views by seniority</span>
                <span class="chip">Views by region</span>
              </div>
              <div class="status ${pageStatistics ? "good" : ""}">${pageStatistics ? "LinkedIn returned page visitor analytics for this page. These are aggregate page-view counts by segment." : "No page visitor analytics were returned for this page."}</div>
              <div class="actions" style="margin-top:18px">
                <a class="button" href="/api/test/org-acls">Refresh Audience Metrics</a>
                <a class="button light" href="/organizations/${organization.organizationId}">Back</a>
              </div>
            </section>
            <section class="section">
              <h2>Content Performance</h2>
              <div class="chips">
                <span class="chip">Clicks: ${shareStatistics?.clickCount?.toLocaleString?.() || 0}</span>
                <span class="chip">Likes: ${shareStatistics?.likeCount?.toLocaleString?.() || 0}</span>
                <span class="chip">Comments: ${shareStatistics?.commentCount?.toLocaleString?.() || 0}</span>
                <span class="chip">Engagement: ${shareStatistics?.engagement ? (shareStatistics.engagement * 100).toFixed(2) + "%" : "0%"}</span>
              </div>
              <p class="muted" style="margin-top:14px">This section comes from LinkedIn's share statistics endpoint. It is not a people list; it is post-performance summary data for the organization.</p>
              <div class="status">Visitor identities are still not exposed here. The available API gives segmented page-view analytics and summary content metrics instead.</div>
            </section>
          </div>
          ${visitorSectionsMarkup ? `<div class="content-grid" style="margin-top:20px">${visitorSectionsMarkup}</div>` : `<section class="section" style="margin-top:20px"><h2>Visitor Segments</h2><p class="muted">No visitor segment analytics were returned for this page yet.</p></section>`}
          <section class="section" style="margin-top:20px">
            <h2>Raw Visitor Analytics Payload</h2>
            <details>
              <summary>Show page statistics JSON</summary>
              <pre>${pageStatisticsPayload}</pre>
            </details>
          </section>
          <section class="section" style="margin-top:20px">
            <h2>Raw Share Performance Payload</h2>
            <details>
              <summary>Show share statistics JSON</summary>
              <pre>${shareStatisticsPayload}</pre>
            </details>
          </section>
        </div>
      </section>
    </div>
    <script>
      const tabs = document.querySelectorAll('[data-tab]');
      const panels = document.querySelectorAll('[data-panel]');

      function activateTab(name) {
        tabs.forEach((tab) => {
          tab.classList.toggle('active', tab.getAttribute('data-tab') === name);
        });
        panels.forEach((panel) => {
          panel.classList.toggle('active', panel.getAttribute('data-panel') === name);
        });
      }

      tabs.forEach((tab) => {
        tab.addEventListener('click', (event) => {
          event.preventDefault();
          const name = tab.getAttribute('data-tab');
          activateTab(name);
          window.location.hash = name;
        });
      });

      if (window.location.hash === '#visitors') {
        activateTab('visitors');
      }
    </script>
  </body>
</html>`;
}

app.get("/organizations/:organizationId", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const organization = await loadOrganizationForRequest(req.params.organizationId);
  if (!organization) {
    return res.status(404).send(
      "Organization not found in the current authenticated session."
    );
  }

  res.send(renderOrganizationPage(organization));
});

app.get("/organizations/:organizationId/followers", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const organization = await loadOrganizationForRequest(req.params.organizationId);
  if (!organization) {
    return res.status(404).send(
      "Organization not found in the current authenticated session."
    );
  }

  res.send(renderFollowerDetailsPage(organization));
});

app.get("/auth/linkedin", (req, res) => {
  const missingEnvVars = getMissingEnvVars();

  if (missingEnvVars.length) {
    return res.status(500).json({
      error: "Missing required environment variables",
      missingEnvVars,
    });
  }

  oauthState = crypto.randomBytes(16).toString("hex");
  return res.redirect(buildAuthorizationUrl());
});

app.get("/callback", async (req, res) => {
  const missingEnvVars = getMissingEnvVars();

  if (missingEnvVars.length) {
    return res.status(500).json({
      error: "Missing required environment variables",
      missingEnvVars,
    });
  }

  if (req.query.error) {
    return res.status(400).json({
      tokenReceived: false,
      oauthError: {
        error: req.query.error,
        errorDescription: req.query.error_description || null,
        state: req.query.state || null,
      },
    });
  }

  if (!req.query.code) {
    return res.status(400).json({
      tokenReceived: false,
      error: "Missing authorization code in callback request.",
    });
  }

  if (!oauthState && tokenStore.accessToken) {
    return res.redirect("/?flash=callback_reused");
  }

  if (!req.query.state || req.query.state !== oauthState) {
    return res.status(400).json({
      tokenReceived: false,
      error: "Invalid OAuth state.",
      expectedStatePresent: Boolean(oauthState),
      receivedState: req.query.state || null,
    });
  }

  try {
    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code",
      code: req.query.code,
      redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
      client_id: process.env.LINKEDIN_CLIENT_ID,
      client_secret: process.env.LINKEDIN_CLIENT_SECRET,
    });

    const tokenResponse = await axios.post(
      "https://www.linkedin.com/oauth/v2/accessToken",
      tokenParams.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    tokenStore = {
      ...createEmptyTokenStore(),
      accessToken: tokenResponse.data.access_token,
      grantedScopes: parseGrantedScopes(tokenResponse.data.scope),
      tokenResponse: tokenResponse.data,
      savedAt: new Date().toISOString(),
      lastResults: null,
    };

    persistTokenStore();
    oauthState = null;

    await runAndPersistTests({
      createPost: req.query.createPost === "1",
      organizationUrn: req.query.organizationUrn,
    });

    return res.redirect("/?flash=login_success");
  } catch (error) {
    oauthState = null;

    return res.status(500).json({
      tokenReceived: false,
      tokenExchangeError: normalizeError(error),
    });
  }
});

app.get("/api/session", (req, res) => {
  res.status(200).json({
    ...getSessionSnapshot(),
    tokenStorePath,
  });
});

app.post("/api/logout", (req, res) => {
  resetTokenStore();
  oauthState = null;

  res.status(200).json({
    ok: true,
    message: "Saved token and cached results removed.",
  });
});

app.post("/api/posts", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const validation = validateOrganizationPostInput(req.body || {});
  if (!validation.ok) {
    return res
      .status(validation.error.status || 400)
      .json({ attempted: true, ...validation });
  }

  const postResult = await createOrganizationPost(
    tokenStore.accessToken,
    validation.organization.organizationUrn,
    {
      commentary: validation.normalizedCommentary,
      lifecycleState: validation.normalizedLifecycleState,
    }
  );

  const responsePayload = {
    attempted: true,
    organizationUrn: validation.organization.organizationUrn,
    organizationName: getOrganizationDisplayName(validation.organization),
    lifecycleState: validation.normalizedLifecycleState,
    commentary: validation.normalizedCommentary,
    ...postResult,
  };

  if (postResult.ok) {
    invalidateOrganizationPostCache(validation.organization.organizationUrn);
  }

  recordPostResult(responsePayload);

  if (!postResult.ok) {
    return res.status(postResult.error?.status || 500).json(responsePayload);
  }

  res.status(201).json(responsePayload);
});

app.get("/api/test/all", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const results = await runAndPersistTests();
  res.status(200).json(results);
});

app.get("/api/test/member", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const results = await runAndPersistTests();
  res.status(200).json(results.memberProfileResult);
});

app.get("/api/test/lite-profile", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const results = await runAndPersistTests();
  res.status(200).json(results.liteProfileResult);
});

app.get("/api/test/email", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const results = await runAndPersistTests();
  res.status(200).json(results.emailAddressResult);
});

app.get("/api/test/org-acls", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const results = await runAndPersistTests();
  res.status(200).json({
    ...results.organizationAclResult,
    organizations: results.organizations,
  });
});

app.get("/api/test/create-post", async (req, res) => {
  if (!requireToken(res)) {
    return;
  }

  const results = await runAndPersistTests({
    createPost: true,
    organizationUrn: req.query.organizationUrn,
  });

  res.status(200).json(results.organizationPostResult);
});

app.listen(port, () => {
  console.log(`LinkedIn capability explorer listening on http://localhost:${port}`);
});
