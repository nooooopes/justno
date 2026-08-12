local HttpService = game:GetService("HttpService")
local baseUrl = "https://YOUR_NETLIFY_SITE.net/.netlify/functions"
local licenseKey = "test"

local function post_json(url, tbl)
    local body = HttpService:JSONEncode(tbl)
    local ok, res = pcall(function()
        return HttpService:PostAsync(url, body, Enum.HttpContentType.ApplicationJson)
    end)
    if not ok then return nil, res end
    return HttpService:JSONDecode(res)
end

local function get_with_auth(url, token)
    local headers = { ["Authorization"] = "Bearer "..token }
    local ok, res = pcall(function()
        return HttpService:GetAsync(url, false, headers)
    end)
    if not ok then return nil, res end
    return HttpService:JSONDecode(res)
end

local resp, err = post_json(baseUrl.."/validate", { key = licenseKey })
if not resp or not resp.ok then warn("Validation failed:", err or (resp and resp.reason) or "unknown"); return end
local token = resp.token

local sresp, serr = get_with_auth(baseUrl.."/script_plain/script1", token)
if not sresp or not sresp.ok then warn("Script fetch failed:", serr or (sresp and sresp.reason) or "unknown"); return end

local ok, fn = pcall(function() return loadstring(sresp.plaintext) end)
if not ok or type(fn) ~= "function" then warn("Compile failed:", fn); return end
local success, runtimeErr = pcall(fn)
if not success then warn("Runtime error:", runtimeErr) end
