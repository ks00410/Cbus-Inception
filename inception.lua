-- Integrates the Inner Range Inception alarm system with C-Bus.
-- Provides long-poll state monitoring (areas, doors, inputs/zones, outputs) and
-- area arm/disarm control via the Inception REST API.
--
-- Resident script usage:
--   require("user.Inception")
--   inception.Resident_Poll()
--
-- Area control usage (from any event script):
--   require("user.Inception")
--   inception.Control_Area(inception.GetAreaId("House"), "Arm")

require("user.secrets")

-- inception is the public module table, registered as a global so C-Bus can
-- call inception.Resident_Poll() and inception.Control_Area() from any script.
local A = {}
inception = A

-- =============================================================================
-- CONFIGURATION
-- All tuneable values are in this section. Edit here; do not change code below.
-- =============================================================================

-- Inception REST API base URL and API token — loaded from the secrets library.
local API_ROOT  = secrets.API_ROOT
local api_token = secrets.api_token

-- HTTP timeout in seconds for standard (non-long-poll) GET requests.
local HTTP_TIMEOUT = 10

-- HTTP timeout in seconds for the long-poll monitor-updates POST request.
-- The Inception server holds the connection for up to 60 s waiting for events;
-- allow a small buffer to avoid premature client-side timeouts.
local HTTP_TIMEOUT_LONGPOLL = 61

-- C-Bus network name that owns all Inception user params.
local CBUS_NETWORK = "Ethernet"

-- Name of the C-Bus user param used as a debug-logging toggle.
-- Set it to true/1 in the C-Bus project to enable verbose logging.
local DEBUG_PARAM = "Debug Logging"

-- Backoff delays (seconds) applied after consecutive failed requests.
-- Indexed by failure count; the last entry is reused for all further failures.
-- 1st failure → 30 s, 2nd → 60 s, 3rd → 120 s, 4th+ → 300 s (5 min).
local BACKOFF_DELAYS = { 30, 60, 120, 300 }

-- =============================================================================
-- MONITOR CONFIG
-- Defines which Inception entities to monitor and which C-Bus user params to
-- write their decoded state into. Entities are matched by name against the
-- Inception system at startup — no GUIDs required here.
--
-- To add or remove a monitored entity, edit only this table.
-- Names must match exactly what is configured in the Inception system.
-- =============================================================================

local MONITOR_CONFIG = {
  areas = {
    { name = "House",              param = "alarmstate"    },
  },
  doors = {
    { name = "Garage Office Door", param = "garagedoor"   },
  },
  inputs = {
    { name = "Hallway",            param = "security_zone1" },
    { name = "Lounge",             param = "security_zone2" },
  },
  outputs = {
    { name = "CCTV",               param = "cctv_output"  },
  },
}

-- Named param constants — kept for backwards compatibility so that external
-- scripts (e.g. arm/disarm triggers) can reference param names without
-- hardcoding strings.
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

-- Defines the long-poll subscription for each entity type.
-- Used both to build the monitor-updates payload and to map response IDs back
-- to entity types when processing state updates.
local SUBSCRIPTIONS = {
  area   = { id = "CBUS-Areas-Monitor",  stateType = "AreaState"   },
  door   = { id = "CBUS-Doors-Monitor",  stateType = "DoorState"   },
  input  = { id = "CBUS-Input-Monitor",  stateType = "InputState"  },
  output = { id = "CBUS-Output-Monitor", stateType = "OutputState" },
}

-- Maps summary response top-level keys to entity types.
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
-- Nil until discovery has completed successfully.
local _entityMap = nil

-- _areaIds maps area names → GUIDs, built during discovery.
-- Used by GetAreaId() so external scripts can look up area GUIDs by name.
local _areaIds = {}

-- timeSinceUpdate tokens returned by the Inception API with each response.
-- Sent back on the next request so the server only returns events newer than
-- the last received update. "0" triggers a full state snapshot on first poll.
local _tsu = {}
for _, t in ipairs(ENTITY_TYPES) do
  _tsu[SUBSCRIPTIONS[t].id] = "0"
end

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

-- Returns true if the "Debug Logging" C-Bus user param is set to a truthy value.
local function isDebuggingEnabled()
  return toboolean(GetUserParam(0, DEBUG_PARAM))
end

-- Writes str to the C-Bus log only when debugEnabled is true.
-- Always pass the cached dbg flag — never call isDebuggingEnabled() per-write.
local function debuglog(str, debugEnabled)
  if debugEnabled then log(str) end
end

-- =============================================================================
-- C-BUS I/O HELPERS
-- =============================================================================
-- GetUserParam and SetUserParam raise hard Lua errors for params that do not
-- exist in the C-Bus project. Both helpers use pcall to handle this safely.

-- Writes a value to a user param.
-- Silently does nothing if value is nil or empty.
-- Logs a warning once per missing param per session (suppressed on repeats
-- unless debug logging is enabled).
local function safeSetUserParam(network, name, value, debugEnabled)
  if value == nil or value == "" then return end
  local ok = pcall(SetUserParam, network, name, value)
  if not ok then
    local key = network .. ":" .. name
    if debugEnabled or not _missingParamWarned[key] then
      log("INCEPTION: UserParam '" .. name .. "' does not exist on network '"
          .. network .. "' – skipping write")
      _missingParamWarned[key] = true
    end
  end
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
local function Inception_Get(endpoint)
  local http = require("socket.http")
  local json = require("json")
  http.TIMEOUT = HTTP_TIMEOUT

  local body, code, _, status = http.request {
    method  = "GET",
    url     = API_ROOT .. "/" .. endpoint,
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
    log("INCEPTION: GET failed to decode JSON response from " .. endpoint)
    return nil
  end

  return decoded
end

-- Sends a POST request to the Inception REST API.
-- Returns the raw response body string on success.
-- Returns nil on HTTP error (triggers backoff) or empty body (normal long-poll
-- timeout — not treated as a failure).
function A.Inception_Post(payload, endpoint)
  local http = require("socket.http")
  local dbg  = isDebuggingEnabled()
  http.TIMEOUT = HTTP_TIMEOUT_LONGPOLL

  local body, code, _, status = http.request {
    method  = "POST",
    url     = API_ROOT .. "/" .. endpoint,
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
--   1. Log all entity names visible to the API user (useful for configuring
--      MONITOR_CONFIG and diagnosing permission issues).
--   2. Match discovered entities by name against MONITOR_CONFIG and build
--      _entityMap with the resolved GUIDs.
--   3. Write each matched entity's current state to C-Bus immediately, so
--      params are populated before the first long-poll response arrives.
-- =============================================================================

local function _discoverEntities()
  local dbg = isDebuggingEnabled()

  log("INCEPTION: starting entity discovery...")

  local entityMap = {}

  for _, entityType in ipairs(ENTITY_TYPES) do
    local summary = Inception_Get(SUMMARY_ENDPOINTS[entityType])
    if not summary then
      log("INCEPTION: could not fetch " .. entityType .. " summary – skipping.")
    else
      local entities = summary[SUMMARY_KEYS[entityType]] or {}

      -- ── Log all available entities of this type ─────────────────────────────
      -- This helps operators identify what names to use in MONITOR_CONFIG and
      -- diagnose cases where the API user lacks permission to see certain items.
      local available = {}
      for _, entry in pairs(entities) do
        available[#available + 1] = entry["EntityInfo"]["Name"]
      end
      table.sort(available)
      if #available > 0 then
        log("INCEPTION: available " .. entityType .. "s – "
            .. table.concat(available, ", "))
      else
        log("INCEPTION: no " .. entityType
            .. "s visible to this API user.")
      end

      -- ── Match MONITOR_CONFIG entries against discovered entities ────────────
      local configEntries = MONITOR_CONFIG[entityType .. "s"] or {}
      for _, cfg in ipairs(configEntries) do
        local matched = false
        for _, entry in pairs(entities) do
          if entry["EntityInfo"]["Name"] == cfg.name then
            local id    = entry["EntityInfo"]["ID"]
            local state = entry["CurrentState"]

            -- Store area GUIDs separately so GetAreaId() can look them up.
            if entityType == "area" then
              _areaIds[cfg.name] = id
            end

            -- Register this entity for long-poll state processing.
            entityMap[#entityMap + 1] = {
              id    = id,
              param = cfg.param,
              type  = entityType,
            }

            -- Write the current state to C-Bus immediately so params are
            -- populated before the first long-poll response arrives.
            local decoded = decodeBitmask(state, FLAGS[entityType])
            safeSetUserParam(CBUS_NETWORK, cfg.param, decoded, dbg)

            debuglog("INCEPTION: mapped " .. entityType .. " '" .. cfg.name
                     .. "' → " .. cfg.param
                     .. " (ID: " .. id .. ")"
                     .. " initial state: " .. decoded, dbg)
            matched = true
            break
          end
        end
        if not matched then
          log("INCEPTION: WARNING – " .. entityType .. " '" .. cfg.name
              .. "' not found in Inception."
              .. " Check the name in MONITOR_CONFIG matches exactly.")
        end
      end
    end
  end

  log("INCEPTION: discovery complete – monitoring "
      .. #entityMap .. " entity/entities.")
  return entityMap
end

-- =============================================================================
-- PUBLIC API FUNCTIONS
-- =============================================================================

-- Returns the Inception GUID for an area by its name, or nil if not found.
-- Populated during entity discovery. Use this in arm/disarm scripts instead
-- of hardcoding GUIDs:
--   inception.Control_Area(inception.GetAreaId("House"), "Arm")
function A.GetAreaId(name)
  local id = _areaIds[name]
  if not id then
    log("INCEPTION: GetAreaId – area '" .. name
        .. "' not found. Has discovery run yet?")
  end
  return id
end

-- Arms or disarms an alarm area.
-- id      : area GUID — use inception.GetAreaId("name") to look up by name.
-- C_type  : one of "Disarm", "Arm", "ArmStay", "ArmSleep"
function A.Control_Area(id, C_type)
  if not id then
    log("INCEPTION: Control_Area called with nil id – ignoring.")
    return nil
  end

  local json    = require("json")
  local payload = json.encode({
    Type            = "ControlArea",
    AreaControlType = C_type,
    Entity          = id,
    ExitDelay       = true,
  })

  local res = A.Inception_Post(payload, "control/area/" .. id .. "/activity")
  if res then
    log("INCEPTION: Area Control – " .. tostring(C_type)
        .. " – Response: " .. res)
  else
    log("INCEPTION: Area Control – " .. tostring(C_type) .. " – no response")
  end
  return res
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

function A.Resident_Poll()
  local dbg = isDebuggingEnabled()

  -- ── Entity discovery ────────────────────────────────────────────────────────
  -- Runs once on the first call. Populates _entityMap with resolved GUIDs and
  -- writes initial state values to C-Bus. On subsequent calls this is a no-op.
  if _entityMap == nil then
    _entityMap = _discoverEntities()
    if #_entityMap == 0 then
      log("INCEPTION: no entities matched MONITOR_CONFIG – check configuration.")
      -- Leave _entityMap as an empty table (not nil) so discovery does not
      -- re-run on every tick if nothing is configured.
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
  -- Subscribe to state changes for all four entity types in a single request.
  -- SUBSCRIPTIONS drives the payload so adding a new entity type only requires
  -- updating that table. timeSinceUpdate tokens ensure only new events return.
  local subscriptions = {}
  for _, entityType in ipairs(ENTITY_TYPES) do
    local sub = SUBSCRIPTIONS[entityType]
    subscriptions[#subscriptions + 1] = {
      ID          = sub.id,
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = sub.stateType, timeSinceUpdate = _tsu[sub.id] },
    }
  end

  local payload = json.encode(subscriptions)

  -- ── Poll the API ────────────────────────────────────────────────────────────
  -- Blocks for up to HTTP_TIMEOUT_LONGPOLL seconds waiting for a state change.
  -- Returns nil if nothing changed (normal) or on error (backoff applied).
  local body = A.Inception_Post(payload, "monitor-updates")
  if isempty(body) then return end

  -- ── Parse response ──────────────────────────────────────────────────────────
  local result = json.pdecode(body)
  if not result then
    log("INCEPTION: failed to decode monitor-updates response – skipping.")
    return
  end

  local responseId = tostring(result["ID"])
  local resultData = result["Result"]

  if not resultData then
    log("INCEPTION: monitor-updates response missing 'Result' field – skipping.")
    return
  end

  local stateData = resultData["stateData"]

  -- Advance the timeSinceUpdate token for this subscription so the next
  -- request only fetches events that are newer than this response.
  if _tsu[responseId] ~= nil then
    _tsu[responseId] = tostring(resultData["updateTime"])
  end

  -- ── Write state to C-Bus ────────────────────────────────────────────────────
  -- For each entity update in the response, find its _entityMap entry and
  -- write the decoded state string to the corresponding C-Bus user param.
  if not stateData then return end

  for i = 1, #stateData do
    local entityId = stateData[i]["ID"]
    for _, entry in ipairs(_entityMap) do
      if entry.id == entityId then
        local flagSet = FLAGS[entry.type]
        if flagSet then
          local status = decodeBitmask(stateData[i]["PublicState"], flagSet)
          safeSetUserParam(CBUS_NETWORK, entry.param, status, dbg)
          debuglog("INCEPTION: " .. entry.param .. " = " .. status, dbg)
        end
        break
      end
    end
  end
end
