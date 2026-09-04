-- =============================================================================
-- inception.lua
-- Integrates the Inner Range Inception alarm system with C-Bus.
--
-- FEATURES:
--   - Long-poll state monitoring for areas, doors, inputs/zones and outputs
--   - Area arm/disarm control with activity progress feedback
--   - Door control (lock, unlock, open, timed unlock, lockout, etc.)
--   - Output control (on, off, toggle, pulse)
--   - Dynamic entity discovery at startup — no GUIDs in secrets required
--   - Live review event monitoring (security and access events)
--   - Exponential backoff when the Inception system is unreachable
--
-- RESIDENT SCRIPT USAGE:
--   require("user.Inception")
--   inception.Resident_Poll()
--
-- CONTROL USAGE (from any C-Bus event script):
--   require("user.Inception")
--   inception.Control_Area(inception.GetEntityId("area", "House"), "Arm")
--   inception.Control_Door(inception.GetEntityId("door", "Garage Office Door"), "Open")
--   inception.Control_Output(inception.GetEntityId("output", "CCTV"), "On")
--
-- =============================================================================
-- REQUIRED C-BUS USER PARAMETERS
-- The following params must exist in the C-Bus project before running.
-- All params are String type unless noted. Network: as set in CBUS_NETWORK.
--
-- Fixed params (always required):
--   Debug Logging      Boolean — set to 1 to enable verbose logging
--   last_alarm_event   Receives the most recent security/access event description
--   alarmstate_detail  Receives the result of the last arm/disarm activity
--
-- Dynamic params (defined by MONITOR_CONFIG below):
--   One String param per entry in MONITOR_CONFIG, named by the "param" field.
--   Example — with the default MONITOR_CONFIG the required params are:
--     alarmstate       Area arm state       e.g. "Armed - Away Arm"
--     garagedoor       Garage door state    e.g. "Locked - Closed"
--     security_zone1   Zone 1 input state   e.g. "Sealed"
--     security_zone2   Zone 2 input state   e.g. "Active"
--     cctv_output      CCTV output state    e.g. "Off"
--
--   To monitor additional entities, add entries to MONITOR_CONFIG and create
--   matching user params in C-Bus with the same names.
-- =============================================================================

local secrets = require("user.secrets")

-- inception is the public module table, registered as a global so C-Bus can
-- call inception.Resident_Poll() and control functions from any script.
local A = {}
inception = A

-- =============================================================================
-- CONSTANTS & DEFAULTS
-- =============================================================================

-- Inception REST API base URL and API token helper
local function getSecrets()
  if type(secrets) == "table" then
    if secrets.inception and type(secrets.inception) == "table" then
      return secrets.inception.API_ROOT or secrets.API_ROOT,
             secrets.inception.api_token or secrets.api_token
    end
    return secrets.API_ROOT, secrets.api_token
  end
  return nil, nil
end

-- HTTP timeout in seconds for standard (non-long-poll) GET requests.
local HTTP_TIMEOUT = 10

-- HTTP timeout in seconds for the long-poll monitor-updates POST request.
-- The Inception server holds the connection for up to 60 s waiting for events;
-- allow a small buffer to avoid premature client-side timeouts.
local HTTP_TIMEOUT_LONGPOLL = 61

-- Default C-Bus network name that owns all Inception user parameters.
local DEFAULT_CBUS_NETWORK = "Ethernet"

-- Default C-Bus user param that receives the most recent security/access review event.
local DEFAULT_REVIEW_EVENT_PARAM = "last_alarm_event"

-- Default C-Bus user param that receives the result of the last area arm/disarm activity.
local DEFAULT_ALARM_DETAIL_PARAM = "alarmstate_detail"

-- Review event categories to subscribe to via LiveReviewEvents.
-- Accepted values: "System", "Audit", "Access", "Security", "Hardware"
local REVIEW_CATEGORIES = "Security,Access"

-- Backoff delays (seconds) applied after consecutive failed requests.
-- Indexed by failure count; the last entry is reused for all further failures.
-- 1st failure → 30 s, 2nd → 60 s, 3rd → 120 s, 4th+ → 300 s (5 min).
local BACKOFF_DELAYS = { 30, 60, 120, 300 }

-- Default monitored entities if not provided in resident script config table.
local DEFAULT_MONITOR_CONFIG = {
  areas = {
    { name = "House",              param = "alarmstate"     },
  },
  doors = {
    { name = "Garage Office Door", param = "garagedoor"    },
  },
  inputs = {
    { name = "Hallway",            param = "security_zone1" },
    { name = "Lounge",             param = "security_zone2" },
  },
  outputs = {
    { name = "CCTV",               param = "cctv_output"   },
  },
}

-- Named param constants — kept for backwards compatibility so that external
-- scripts can reference param names without hardcoding strings.
A.CBUS_USERPARAM_NAME_ALARMSTATE = "alarmstate"
A.CBUS_USERPARAM_NAME_FRONTDOOR  = "frontdoor"
A.CBUS_USERPARAM_NAME_REARDOOR   = "reardoor"
A.CBUS_USERPARAM_NAME_ZONES = {
  "security_zone1", "security_zone2", "security_zone3", "security_zone4",
  "security_zone5", "security_zone6", "security_zone7", "security_zone8",
}

-- =============================================================================
-- LOOKUP TABLES
-- Static data tables used throughout the script.
-- =============================================================================

-- Bitmask label arrays for each entity type.
-- Bit position 0 (value 1) maps to index 1, bit 1 (value 2) to index 2, etc.
-- Values match the Inception REST API *PublicStates enumerations.

local AREA_FLAGS = {
  "Armed", "Alarm", "Entry Delay", "Exit Delay", "Arm Warning",
  "Defer Disarmed", "Detecting Active Inputs", "Walk Test Active",
  "Away Arm", "Stay Arm", "Sleep Arm", "Disarmed", "Arm Ready",
}

local DOOR_FLAGS = {
  "Unlocked", "Open", "Locked Out", "Forced", "Held Open Warning",
  "Held Open Too Long", "Breakglass", "Reader Tamper", "Locked", "Closed",
  "Held Response Muted", "Battery Low", "Lock Offline",
}

local INPUT_FLAGS = {
  "Active", "Tamper", "Isolated", "Mask", "Low Battery", "Poll Failed",
  "Sealed", "Wireless Door Battery Low", "Wireless Door Lock Offline",
}

local OUTPUT_FLAGS = {
  "On", "Off",
}

-- Maps entity type strings to their bitmask flag arrays.
local FLAGS = {
  area   = AREA_FLAGS,
  door   = DOOR_FLAGS,
  input  = INPUT_FLAGS,
  output = OUTPUT_FLAGS,
}

-- Defines the long-poll subscription for each entity state type.
-- Used to build the monitor-updates payload and map response IDs to types.
local SUBSCRIPTIONS = {
  area   = { id = "CBUS-Areas-Monitor",  stateType = "AreaState"   },
  door   = { id = "CBUS-Doors-Monitor",  stateType = "DoorState"   },
  input  = { id = "CBUS-Input-Monitor",  stateType = "InputState"  },
  output = { id = "CBUS-Output-Monitor", stateType = "OutputState" },
}

-- Maps summary response top-level JSON keys to entity types.
local SUMMARY_KEYS = {
  area   = "Areas",
  door   = "Doors",
  input  = "Inputs",
  output = "Outputs",
}

-- Maps entity types to their summary GET endpoints.
local SUMMARY_ENDPOINTS = {
  area   = "control/area/summary",
  door   = "control/door/summary",
  input  = "control/input/summary",
  output = "control/output/summary",
}

-- Ordered list of entity types — controls discovery and subscription order.
local ENTITY_TYPES = { "area", "door", "input", "output" }

-- =============================================================================
-- MODULE STATE
-- Variables that persist between poll cycles.
-- =============================================================================

-- _entityMap is built dynamically by _discoverEntities() on the first poll.
-- Each entry: { id (GUID), param (C-Bus user param name), type (entity type) }
-- Nil until discovery has completed; set to {} if discovery finds nothing.
local _entityMap = nil

-- _entityIds maps { type → { name → GUID } } for all discovered entities.
-- Used by GetEntityId() so external scripts can look up GUIDs by friendly name.
local _entityIds = {}

-- timeSinceUpdate tokens returned by the Inception API with each response.
-- Sent back on the next request so the server only returns events newer than
-- the last received update. "0" triggers a full state snapshot on first poll.
local _tsu = {}
for _, t in ipairs(ENTITY_TYPES) do
  _tsu[SUBSCRIPTIONS[t].id] = "0"
end

-- LiveReviewEvents reference fields — updated after each received review event
-- so the next request only returns events newer than the last received one.
local _reviewReferenceId   = ""
local _reviewReferenceTime = ""

-- Tracks pending activity IDs awaiting progress results.
-- Maps activityId → { label } so progress responses can be labelled in the log.
local _pendingActivities = {}

-- Consecutive API failure count and the earliest os.time() at which the next
-- request is permitted. Both reset to 0 on any successful response.
local _failCount  = 0
local _retryAfter = 0

-- Tracks which "missing param" warnings have already been logged so the
-- C-Bus log is not flooded with the same message on every poll cycle.
local _missingParamWarned = {}

-- =============================================================================
-- LOGGING HELPERS
-- =============================================================================

-- Returns true if explicit_debug is true or if the C-Bus user param evaluates directly to boolean true.
local function isDebuggingEnabled(network, debug_param, explicit_debug)
  if explicit_debug == true then return true end
  if debug_param and type(debug_param) == "string" and #debug_param > 0 then
    local net = network or DEFAULT_CBUS_NETWORK
    local ok, val = pcall(GetUserParam, net, debug_param)
    return ok and val == true
  end
  return false
end

-- Writes str to the C-Bus log only when debugEnabled is true.
-- Always pass the cached dbg flag — never call isDebuggingEnabled() per-write.
local function debuglog(str, debugEnabled)
  if debugEnabled then log("INCEPTION [DEBUG]: " .. tostring(str)) end
end

-- =============================================================================
-- C-BUS I/O HELPERS
-- =============================================================================
-- GetUserParam and SetUserParam raise hard Lua errors for params that do not
-- exist in the C-Bus project. Both helpers use pcall to handle this safely.

-- Reads a user param. Returns the value on success, or nil on error.
local function safeGetUserParam(network, name)
  local ok, val = pcall(GetUserParam, network, name)
  return ok and val or nil
end

-- Writes a value to a user param.
-- Silently does nothing if value is nil or empty.
-- Logs a warning once per missing param per session (suppressed on repeats
-- unless debug logging is enabled).
local function safeSetUserParam(network, name, value, debugEnabled)
  if value == nil or value == "" then return end
  local ok = pcall(SetUserParam, network, name, value)
  if not ok then
    local key = tostring(network) .. ":" .. tostring(name)
    if debugEnabled or not _missingParamWarned[key] then
      log("INCEPTION: UserParam '" .. tostring(name) .. "' does not exist on network '"
          .. tostring(network) .. "' – skipping write")
      _missingParamWarned[key] = true
    end
  end
end

-- Resolve C-Bus UserParam name (checks config.cbus_params overrides first, then falls back to prefix or default)
local function getParamName(config, name)
  local params = config and config.cbus_params
  if params and params[name] then
    return params[name]
  end
  local pfx = (config and config.param_prefix) or ""
  return pfx .. name
end

-- =============================================================================
-- UTILITY FUNCTIONS
-- =============================================================================

-- Returns true when s is nil or an empty string.
local function isempty(s)
  return s == nil or s == ""
end

-- Decodes an Inception PublicState bitmask integer into a human-readable
-- dash-separated string using the provided flag label array.
-- Example: decodeBitmask(3, AREA_FLAGS) → "Armed - Alarm"
-- Returns an empty string if no flags are set.
local function decodeBitmask(value, flags)
  local parts = {}
  for i = 0, #flags - 1 do
    if bit.band(value, 2^i) > 0 then
      parts[#parts + 1] = flags[i + 1]
    end
  end
  return table.concat(parts, " - ")
end

-- =============================================================================
-- BACKOFF HELPERS
-- =============================================================================

-- Called after every failed request. Increments the failure counter and
-- sets _retryAfter to prevent further requests until the backoff window expires.
local function _recordFailure()
  _failCount = _failCount + 1
  local delay = BACKOFF_DELAYS[math.min(_failCount, #BACKOFF_DELAYS)]
  _retryAfter = os.time() + delay
  log("INCEPTION: offline or no response (failure #" .. _failCount
      .. ") – backing off for " .. delay .. " s.")
end

-- Called after every successful response. Resets backoff state and logs a
-- recovery message if requests had previously been failing.
local function _recordSuccess()
  if _failCount > 0 then
    log("INCEPTION: connection restored after " .. _failCount .. " failure(s).")
  end
  _failCount  = 0
  _retryAfter = 0
end

-- =============================================================================
-- HTTP FUNCTIONS
-- =============================================================================

-- Sends a GET request to the Inception REST API.
-- Returns the decoded JSON table on success, or nil on HTTP error or bad JSON.
local function Inception_Get(endpoint, api_root_override, token_override)
  local http = require("socket.http")
  local json = require("json")
  http.TIMEOUT = HTTP_TIMEOUT

  local api_root, api_token = getSecrets()
  api_root = api_root_override or api_root
  api_token = token_override or api_token

  if not api_root or not api_token then
    log("INCEPTION: Missing API_ROOT or api_token in secrets or configuration.")
    return nil
  end

  local body, code, _, status = http.request {
    method  = "GET",
    url     = api_root .. "/" .. endpoint,
    headers = {
      ["Accept"]        = "application/json",
      ["Authorization"] = "APIToken " .. api_token,
    },
  }

  if code ~= 200 then
    log("INCEPTION: GET error " .. tostring(code)
        .. " on " .. endpoint .. " – " .. tostring(body))
    return nil
  elseif isempty(body) then
    log("INCEPTION: GET empty response on " .. endpoint)
    return nil
  end

  local decoded = json.pdecode(body)
  if not decoded then
    log("INCEPTION: GET failed to decode JSON from " .. endpoint)
    return nil
  end

  return decoded
end

-- Sends a POST request to the Inception REST API.
-- Returns the raw response body string on success.
-- Returns nil on HTTP error (triggers backoff) or empty body (normal long-poll
-- timeout — not treated as a failure).
function A.Inception_Post(payload, endpoint, dbg, api_root_override, token_override)
  local http = require("socket.http")
  http.TIMEOUT = HTTP_TIMEOUT_LONGPOLL

  local api_root, api_token = getSecrets()
  api_root = api_root_override or api_root
  api_token = token_override or api_token

  if not api_root or not api_token then
    log("INCEPTION: Missing API_ROOT or api_token in secrets or configuration.")
    return nil
  end

  local body, code, _, status = http.request {
    method  = "POST",
    url     = api_root .. "/" .. endpoint,
    headers = {
      ["Accept"]        = "application/json",
      ["Authorization"] = "APIToken " .. api_token,
    },
    body = payload,
  }

  debuglog("INCEPTION POST /" .. endpoint
    .. "\n  code:   " .. tostring(code)
    .. "\n  status: " .. tostring(status)
    .. "\n  body:   " .. tostring(body), dbg)

  if code ~= 200 then
    log("INCEPTION: POST error " .. tostring(code)
        .. " on " .. endpoint .. " – " .. tostring(body))
    _recordFailure()
    return nil
  elseif isempty(body) then
    -- An empty body on monitor-updates means no events arrived in 60 s — normal.
    _recordSuccess()
    return nil
  else
    _recordSuccess()
    return body
  end
end

-- =============================================================================
-- ENTITY DISCOVERY
-- Called once on the first Resident_Poll cycle. Fetches summary data from the
-- Inception API to:
--   1. Log the system name and serial number.
--   2. Log all entity names visible to the API user (useful for configuring
--      MONITOR_CONFIG and diagnosing permission issues).
--   3. Match discovered entities by name against MONITOR_CONFIG and build
--      _entityMap with the resolved GUIDs.
--   4. Write each matched entity's current state to C-Bus immediately, so
--      params are populated before the first long-poll response arrives.
-- =============================================================================

local function _discoverEntities(cfg_obj, cbus_net, dbg)
  local monitor_tbl = cfg_obj and (cfg_obj.monitor or cfg_obj.MONITOR_CONFIG) or DEFAULT_MONITOR_CONFIG
  local api_root_override = cfg_obj and cfg_obj.api_url
  local token_override    = cfg_obj and cfg_obj.api_token

  -- ── System info ─────────────────────────────────────────────────────────────
  -- Log the system name and serial number so it is easy to confirm which
  -- Inception controller the script is connected to.
  local sysinfo = Inception_Get("api/v1/system-info", api_root_override, token_override)
  if sysinfo then
    log("INCEPTION: connected to '" .. tostring(sysinfo["SystemName"])
        .. "' [S/N: " .. tostring(sysinfo["SerialNumber"]) .. "]")
  end

  log("INCEPTION: starting entity discovery...")

  local entityMap = {}

  for _, entityType in ipairs(ENTITY_TYPES) do
    local summary = Inception_Get(SUMMARY_ENDPOINTS[entityType], api_root_override, token_override)
    if not summary then
      log("INCEPTION: could not fetch " .. entityType .. " summary – skipping.")
    else
      local entities = summary[SUMMARY_KEYS[entityType]]
      if type(entities) ~= "table" then
        log("INCEPTION: unexpected response format for " .. entityType
            .. " summary – skipping.")
      else

      -- ── Log all available entities of this type ─────────────────────────────
      -- Helps operators identify names for MONITOR_CONFIG and diagnose cases
      -- where the API user lacks permission to see certain items.
      local available = {}
      for _, entry in pairs(entities) do
        available[#available + 1] = entry["EntityInfo"]["Name"]
      end
      table.sort(available)
      if #available > 0 then
        log("INCEPTION: available " .. entityType .. "s – "
            .. table.concat(available, ", "))
      else
        log("INCEPTION: no " .. entityType .. "s visible to this API user.")
      end

      -- ── Build _entityIds lookup for this type ───────────────────────────────
      -- Populated for all discovered entities (not just monitored ones) so that
      -- GetEntityId() can resolve any entity for control scripts.
      _entityIds[entityType] = _entityIds[entityType] or {}
      for _, entry in pairs(entities) do
        _entityIds[entityType][entry["EntityInfo"]["Name"]] = entry["EntityInfo"]["ID"]
      end

      -- ── Match MONITOR_CONFIG entries against discovered entities ────────────
      local configEntries = monitor_tbl[entityType .. "s"] or {}
      for _, cfg in ipairs(configEntries) do
        local id = _entityIds[entityType][cfg.name]
        if not id then
          log("INCEPTION: WARNING – " .. entityType .. " '" .. cfg.name
              .. "' not found in Inception."
              .. " Check the name in MONITOR_CONFIG matches exactly.")
        else
          -- Retrieve CurrentState from the summary for the initial C-Bus write.
          local state = 0
          for _, entry in pairs(entities) do
            if entry["EntityInfo"]["Name"] == cfg.name then
              state = entry["CurrentState"] or 0
              break
            end
          end

          local param_name = getParamName(cfg_obj, cfg.param or cfg.name)

          -- Register this entity for long-poll state processing.
          entityMap[#entityMap + 1] = {
            id    = id,
            param = param_name,
            type  = entityType,
          }

          -- Write the current state to C-Bus immediately so params are
          -- populated before the first long-poll response arrives.
          local decoded = decodeBitmask(state, FLAGS[entityType])
          safeSetUserParam(cbus_net, param_name, decoded, dbg)

          debuglog("INCEPTION: mapped " .. entityType .. " '" .. cfg.name
                   .. "' → " .. param_name
                   .. " (ID: " .. id .. ")"
                   .. " initial state: " .. decoded, dbg)
        end
      end
      end -- type check
    end
  end

  log("INCEPTION: discovery complete – monitoring "
      .. #entityMap .. " entity/entities.")
  return entityMap
end

-- =============================================================================
-- RESPONSE HANDLERS
-- Private functions that process each type of long-poll response.
-- =============================================================================

-- Handles a MonitorEntityStates response — decodes updated entity states and
-- writes them to their corresponding C-Bus user params.
local function _handleEntityStates(result, cbus_net, dbg)
  local responseId = tostring(result["ID"])
  local resultData = result["Result"]

  if not resultData then
    log("INCEPTION: MonitorEntityStates response missing 'Result' field.")
    return
  end

  -- Advance the timeSinceUpdate token so the next request fetches only newer events.
  if _tsu[responseId] ~= nil then
    _tsu[responseId] = tostring(resultData["updateTime"])
  end

  local stateData = resultData["stateData"]
  if not stateData then return end

  for i = 1, #stateData do
    local entityId   = stateData[i]["ID"]
    local publicState = stateData[i]["PublicState"]
    if publicState == nil then
      debuglog("INCEPTION: entity " .. tostring(entityId)
               .. " has no PublicState – skipping.", dbg)
    else
      for _, entry in ipairs(_entityMap) do
        if entry.id == entityId then
          local flagSet = FLAGS[entry.type]
          if flagSet then
            local status = decodeBitmask(publicState, flagSet)
            safeSetUserParam(cbus_net, entry.param, status, dbg)
            debuglog("INCEPTION: " .. entry.param .. " = " .. status, dbg)
          end
          break
        end
      end
    end
  end
end

-- Handles a LiveReviewEvents response — writes the most recent event description
-- to REVIEW_EVENT_PARAM and advances the reference tokens for the next request.
local function _handleReviewEvents(result, review_param, cbus_net, dbg)
  local events = result["Result"]
  if not events or #events == 0 then return end

  -- The most recent event is the last entry (events are returned in ascending order).
  local latest = events[#events]

  -- Advance the reference tokens so the next request only returns newer events.
  -- Guard against tostring(nil) producing "nil" — use raw value checks first.
  _reviewReferenceId   = latest["Id"]            and tostring(latest["Id"])            or ""
  _reviewReferenceTime = latest["ReferenceTime"] and tostring(latest["ReferenceTime"])
                      or latest["WhenTicks"]     and tostring(latest["WhenTicks"])
                      or ""

  -- Build a readable label from description, who, and timestamp.
  local description = tostring(latest["Description"] or "")
  local when        = tostring(latest["When"]         or "")
  local who         = tostring(latest["Who"]          or "")

  local label = description
  if who ~= "" and who ~= "nil" then
    label = label .. " (" .. who .. ")"
  end
  if when ~= "" and when ~= "nil" then
    label = label .. " @ " .. when
  end

  safeSetUserParam(cbus_net, review_param, label, dbg)
  debuglog("INCEPTION: review event – " .. label, dbg)

  -- When debug is on, log every received event for full visibility.
  if dbg then
    for i = 1, #events do
      local e = events[i]
      log("INCEPTION: event – " .. tostring(e["Description"])
          .. " | " .. tostring(e["When"])
          .. " | who: " .. tostring(e["Who"]))
    end
  end
end

-- Handles an ActivityProgress response — logs the arm/disarm result and writes
-- it to ALARM_DETAIL_PARAM. Removes the activity from _pendingActivities once
-- it reaches a terminal state (Success or Failure).
local function _handleActivityProgress(result, detail_param, cbus_net, dbg)
  local resultData = result["Result"]
  if not resultData then return end

  local actId   = resultData["ActivityId"] and tostring(resultData["ActivityId"]) or ""
  local pending = _pendingActivities[actId]
  local msgs    = resultData["Messages"]
  if not msgs or #msgs == 0 then return end

  -- Warn if we receive progress for an activity we are not tracking.
  -- This can happen if the script restarted mid-activity.
  if actId == "" then
    debuglog("INCEPTION: received activity progress with no ActivityId – skipping.", dbg)
    return
  end
  if not pending then
    debuglog("INCEPTION: received progress for unknown activity "
             .. actId .. " – may be stale, ignoring.", dbg)
  end

  for i = 1, #msgs do
    local msg   = msgs[i]
    local state = msg["Type"]   -- 0=Running, 1=RunningNoCancel, 2=Success, 3=Failure
    local text  = tostring(msg["Message"] or "")

    if state == 2 then
      -- Terminal: activity succeeded.
      local label = "Success"
      log("INCEPTION: activity " .. (pending and pending.label or actId)
          .. " – Success")
      safeSetUserParam(cbus_net, detail_param, label, dbg)
      _pendingActivities[actId] = nil

    elseif state == 3 then
      -- Terminal: activity failed.
      local label = "Failed: " .. text
      log("INCEPTION: activity " .. (pending and pending.label or actId)
          .. " – FAILED: " .. text)
      safeSetUserParam(cbus_net, detail_param, label, dbg)
      _pendingActivities[actId] = nil

    else
      -- Non-terminal: still running — log at debug level only.
      debuglog("INCEPTION: activity " .. (pending and pending.label or actId)
               .. " – in progress: " .. text, dbg)
    end
  end
end

-- =============================================================================
-- PUBLIC API FUNCTIONS
-- =============================================================================

-- Returns the Inception GUID for any entity by type and name.
-- Populated during entity discovery on the first Resident_Poll call.
-- Use in control scripts instead of hardcoding GUIDs:
--   inception.Control_Area(inception.GetEntityId("area", "House"), "Arm")
--   inception.Control_Door(inception.GetEntityId("door", "Garage Office Door"), "Open")
function A.GetEntityId(entityType, name)
  local typeMap = _entityIds[entityType]
  if not typeMap then
    log("INCEPTION: GetEntityId – unknown entity type '" .. tostring(entityType)
        .. "'. Has discovery run yet?")
    return nil
  end
  local id = typeMap[name]
  if not id then
    log("INCEPTION: GetEntityId – " .. tostring(entityType) .. " '"
        .. tostring(name) .. "' not found. Has discovery run yet?")
  end
  return id
end

-- Arms or disarms an alarm area and registers the activity for progress monitoring.
-- id     : area GUID — use inception.GetEntityId("area", "House")
-- C_type : "Disarm", "Arm", "ArmStay", or "ArmSleep"
function A.Control_Area(id, C_type, config_override)
  if not id then
    log("INCEPTION: Control_Area called with nil id – ignoring.")
    return nil
  end
  if not C_type then
    log("INCEPTION: Control_Area called with nil C_type – ignoring.")
    return nil
  end

  local cfg = config_override or {}
  local CBUS_NETWORK = cfg.cbus_network or DEFAULT_CBUS_NETWORK
  local dbg = isDebuggingEnabled(CBUS_NETWORK, cfg.debug_param, cfg.debug)
  local detail_param = getParamName(cfg, "alarmstate_detail")

  local json    = require("json")
  local payload = json.encode({
    Type            = "ControlArea",
    AreaControlType = C_type,
    Entity          = id,
    ExitDelay       = true,
  })

  local body = A.Inception_Post(payload, "control/area/" .. id .. "/activity", dbg, cfg.api_url, cfg.api_token)
  if not body then
    log("INCEPTION: Control_Area – " .. tostring(C_type) .. " – no response")
    return nil
  end

  -- Decode the ActivityResponse to get the result and the new activity ID.
  -- The activity ID is registered for progress monitoring via the long-poll.
  local response = json.pdecode(body)
  if not response then
    log("INCEPTION: Control_Area – could not decode response")
    return nil
  end

  local result  = response["Response"] and response["Response"]["Result"]  or "Unknown"
  local message = response["Response"] and response["Response"]["Message"] or ""
  local actId   = response["ActivityID"]

  if result == "Success" then
    log("INCEPTION: Control_Area – " .. tostring(C_type) .. " – accepted"
        .. (actId and (" (activity: " .. actId .. ")") or ""))
    -- Register for progress monitoring so arm success/failure is fed back to C-Bus.
    if actId then
      _pendingActivities[actId] = { label = C_type }
    end
  else
    log("INCEPTION: Control_Area – " .. tostring(C_type)
        .. " – FAILED: " .. message)
    safeSetUserParam(CBUS_NETWORK, detail_param,
                     "Failed: " .. message, dbg)
  end

  return response
end

-- Controls a door.
-- id       : door GUID — use inception.GetEntityId("door", "Garage Office Door")
-- C_type   : "Lock", "Unlock", "Open", "TimedUnlock", "Lockout",
--            "Reinstate", "ToggleLock", "MuteHeldResponse", "CancelAccessRequests"
-- timeSecs : (optional) duration in seconds for timed operations e.g. TimedUnlock
function A.Control_Door(id, C_type, timeSecs, config_override)
  if not id then
    log("INCEPTION: Control_Door called with nil id – ignoring.")
    return nil
  end
  if not C_type then
    log("INCEPTION: Control_Door called with nil C_type – ignoring.")
    return nil
  end

  local cfg = config_override or {}
  local CBUS_NETWORK = cfg.cbus_network or DEFAULT_CBUS_NETWORK
  local dbg = isDebuggingEnabled(CBUS_NETWORK, cfg.debug_param, cfg.debug)

  local json    = require("json")
  local payload = { Type = "ControlDoor", DoorControlType = C_type, Entity = id }
  if timeSecs then payload["TimeSecs"] = timeSecs end

  local body = A.Inception_Post(json.encode(payload),
                                "control/door/" .. id .. "/activity", dbg, cfg.api_url, cfg.api_token)
  if not body then
    log("INCEPTION: Control_Door – " .. tostring(C_type) .. " – no response")
    return nil
  end

  local response = json.pdecode(body)
  if not response then
    log("INCEPTION: Control_Door – could not decode response")
    return nil
  end

  local result  = response["Response"] and response["Response"]["Result"]  or "Unknown"
  local message = response["Response"] and response["Response"]["Message"] or ""

  if result == "Success" then
    log("INCEPTION: Control_Door – " .. tostring(C_type) .. " – accepted")
  else
    log("INCEPTION: Control_Door – " .. tostring(C_type)
        .. " – FAILED: " .. message)
  end

  return response
end

-- Controls an output.
-- id       : output GUID — use inception.GetEntityId("output", "CCTV")
-- C_type   : "On", "Off", "Toggle", or "Pulse"
-- timeSecs : (optional) duration in seconds — output returns to previous state
--            after this time. Applicable to On and Pulse.
function A.Control_Output(id, C_type, timeSecs, config_override)
  if not id then
    log("INCEPTION: Control_Output called with nil id – ignoring.")
    return nil
  end
  if not C_type then
    log("INCEPTION: Control_Output called with nil C_type – ignoring.")
    return nil
  end

  local cfg = config_override or {}
  local CBUS_NETWORK = cfg.cbus_network or DEFAULT_CBUS_NETWORK
  local dbg = isDebuggingEnabled(CBUS_NETWORK, cfg.debug_param, cfg.debug)

  local json    = require("json")
  local payload = { Type = "ControlOutput", OutputControlType = C_type, Entity = id }
  if timeSecs then payload["TimeSecs"] = timeSecs end

  local body = A.Inception_Post(json.encode(payload),
                                "control/output/" .. id .. "/activity", dbg, cfg.api_url, cfg.api_token)
  if not body then
    log("INCEPTION: Control_Output – " .. tostring(C_type) .. " – no response")
    return nil
  end

  local response = json.pdecode(body)
  if not response then
    log("INCEPTION: Control_Output – could not decode response")
    return nil
  end

  local result  = response["Response"] and response["Response"]["Result"]  or "Unknown"
  local message = response["Response"] and response["Response"]["Message"] or ""

  if result == "Success" then
    log("INCEPTION: Control_Output – " .. tostring(C_type) .. " – accepted")
  else
    log("INCEPTION: Control_Output – " .. tostring(C_type)
        .. " – FAILED: " .. message)
  end

  return response
end

-- Clears the entity map and re-runs discovery on the next poll cycle.
-- Call from a C-Bus event script when the Inception system has been reconfigured
-- (e.g. new zones added, entities renamed) without restarting the resident script.
function A.ResetDiscovery()
  log("INCEPTION: ResetDiscovery called – will re-discover on next poll.")
  _entityMap = nil
  _entityIds = {}
end

-- Decodes an AreaPublicStates bitmask into a readable state string.
function A.areaeval(res)   return decodeBitmask(res, AREA_FLAGS)   end

-- Decodes a DoorPublicStates bitmask into a readable state string.
function A.dooreval(res)   return decodeBitmask(res, DOOR_FLAGS)   end

-- Decodes an InputPublicStates bitmask into a readable state string.
function A.inputeval(res)  return decodeBitmask(res, INPUT_FLAGS)  end

-- Decodes an OutputPublicStates bitmask into a readable state string.
function A.outputeval(res) return decodeBitmask(res, OUTPUT_FLAGS) end

-- =============================================================================
-- RESIDENT POLL
-- Called on every timer tick by the C-Bus resident script.
-- =============================================================================

function A.Resident_Poll(config)
  local cfg = config or {}
  local CBUS_NETWORK = cfg.cbus_network or DEFAULT_CBUS_NETWORK
  local dbg = isDebuggingEnabled(CBUS_NETWORK, cfg.debug_param, cfg.debug)
  local review_param = getParamName(cfg, "last_alarm_event")
  local detail_param = getParamName(cfg, "alarmstate_detail")

  -- ── Entity discovery ────────────────────────────────────────────────────────
  -- Runs once on the first call. Logs system info and available entities,
  -- resolves MONITOR_CONFIG names to GUIDs, and writes initial state to C-Bus.
  -- On subsequent calls this block is a no-op.
  if _entityMap == nil then
    _entityMap = _discoverEntities(cfg, CBUS_NETWORK, dbg)
    if #_entityMap == 0 then
      log("INCEPTION: no entities matched MONITOR_CONFIG – check configuration.")
    end
  end

  -- ── Backoff check ───────────────────────────────────────────────────────────
  -- Skip the poll entirely while within a backoff window caused by a previous
  -- failure. Only logged at debug level to avoid filling the log during outages.
  if os.time() < _retryAfter then
    debuglog("INCEPTION: skipping poll – backing off for another "
             .. (_retryAfter - os.time()) .. " s.", dbg)
    return
  end

  local json = require("json")

  -- ── Build long-poll payload ─────────────────────────────────────────────────
  -- Subscribe to entity state changes, live review events, and any pending
  -- activity progress updates — all in a single long-poll request.
  local subscriptions = {}

  -- Entity state subscriptions (area, door, input, output).
  -- Driven by SUBSCRIPTIONS table so no changes needed here when adding types.
  for _, entityType in ipairs(ENTITY_TYPES) do
    local sub = SUBSCRIPTIONS[entityType]
    subscriptions[#subscriptions + 1] = {
      ID          = sub.id,
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = sub.stateType, timeSinceUpdate = _tsu[sub.id] },
    }
  end

  -- Live review events — streams security and access events in real time.
  subscriptions[#subscriptions + 1] = {
    ID          = "CBUS-Review-Monitor",
    RequestType = "LiveReviewEvents",
    InputData   = {
      referenceId    = _reviewReferenceId,
      referenceTime  = _reviewReferenceTime,
      categoryFilter = REVIEW_CATEGORIES,
    },
  }

  -- Activity progress — one subscription per pending arm/disarm activity.
  for actId, info in pairs(_pendingActivities) do
    subscriptions[#subscriptions + 1] = {
      ID          = "CBUS-Activity-" .. actId,
      RequestType = "ActivityProgress",
      InputData   = { activityId = actId, receivedMsgs = "" },
    }
    debuglog("INCEPTION: monitoring progress for activity "
             .. info.label .. " (" .. actId .. ")", dbg)
  end

  local payload = json.encode(subscriptions)

  -- ── Poll the API ────────────────────────────────────────────────────────────
  -- Blocks for up to HTTP_TIMEOUT_LONGPOLL seconds waiting for any event.
  -- Returns nil if nothing changed (normal) or on error (backoff applied).
  local body = A.Inception_Post(payload, "monitor-updates", dbg, cfg.api_url, cfg.api_token)
  if isempty(body) then return end

  -- ── Parse and dispatch response ─────────────────────────────────────────────
  -- The API returns one UpdateMonitorRequestResult per poll response.
  -- Dispatch to the appropriate handler based on the subscription ID.
  local result = json.pdecode(body)
  if not result then
    log("INCEPTION: failed to decode monitor-updates response – skipping.")
    return
  end

  local responseId = tostring(result["ID"] or "")

  if responseId == "CBUS-Review-Monitor" then
    _handleReviewEvents(result, review_param, CBUS_NETWORK, dbg)

  elseif responseId:find("^CBUS%-Activity%-") then
    _handleActivityProgress(result, detail_param, CBUS_NETWORK, dbg)

  elseif result["Result"] and result["Result"]["stateData"] then
    _handleEntityStates(result, CBUS_NETWORK, dbg)

  else
    debuglog("INCEPTION: unhandled response ID: " .. responseId, dbg)
  end
end
