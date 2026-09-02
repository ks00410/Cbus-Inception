-- Integrates the Inner Range Inception alarm system with C-Bus.
-- Provides long-poll state monitoring (areas, doors, inputs/zones) and
-- area arm/disarm control via the Inception REST API.
--
-- Resident script usage:
--   require("user.Inception")
--   inception.Resident_Poll()

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

-- HTTP timeout in seconds for Inception API calls.
-- The long-poll endpoint holds for up to 60 s; allow a small buffer.
local HTTP_TIMEOUT = 61

-- C-Bus network name that owns all Inception user params.
local CBUS_NETWORK = "Ethernet"

-- Name of the C-Bus user param used as a debug-logging toggle.
-- Set it to true/1 in the C-Bus project to enable verbose output.
local DEBUG_PARAM = "Debug Logging"

-- Backoff delays (seconds) applied after consecutive failed requests.
-- Indexed by failure count; the last entry is used for all further failures.
-- e.g. 1st failure → 30 s, 2nd → 60 s, 3rd → 120 s, 4th+ → 300 s (5 min).
local BACKOFF_DELAYS = { 30, 60, 120, 300 }

-- =============================================================================
-- ENTITY MAP
-- Maps each monitored Inception entity to its C-Bus user param and state type.
-- To add or remove a monitored entity, edit only this table.
-- =============================================================================

-- Each entry:
--   id    : Inception entity GUID (from secrets)
--   param : C-Bus user param name to write the decoded state string into
--   type  : "area" | "door" | "input" — selects the bitmask decoder

local ENTITY_MAP = {
  -- Alarm area
  { id = secrets.area_id,       param = "alarmstate",     type = "area"  },
  -- Doors
  { id = secrets.front_door_id, param = "frontdoor",      type = "door"  },
  { id = secrets.rear_door_id,  param = "reardoor",       type = "door"  },
  -- Zones / inputs
  { id = secrets.zone1,         param = "security_zone1", type = "input" },
  { id = secrets.zone2,         param = "security_zone2", type = "input" },
  { id = secrets.zone3,         param = "security_zone3", type = "input" },
  { id = secrets.zone4,         param = "security_zone4", type = "input" },
  { id = secrets.zone5,         param = "security_zone5", type = "input" },
  { id = secrets.zone6,         param = "security_zone6", type = "input" },
  { id = secrets.zone7,         param = "security_zone7", type = "input" },
  { id = secrets.zone8,         param = "security_zone8", type = "input" },
}

-- Named param constants — kept for backwards compatibility so that external
-- scripts (e.g. arm/disarm triggers) can reference them without hardcoding strings.
A.CBUS_USERPARAM_NAME_ALARMSTATE = "alarmstate"
A.CBUS_USERPARAM_NAME_FRONTDOOR  = "frontdoor"
A.CBUS_USERPARAM_NAME_REARDOOR   = "reardoor"
A.CBUS_USERPARAM_NAME_ZONES = {
  "security_zone1", "security_zone2", "security_zone3", "security_zone4",
  "security_zone5", "security_zone6", "security_zone7", "security_zone8",
}

-- =============================================================================
-- LOOKUP TABLES
-- Static bitmask label arrays for each entity type.
-- Bit position 0 (value 1) maps to index 1, bit 1 (value 2) to index 2, etc.
-- Values match the Inception REST API AreaPublicStates / DoorPublicStates /
-- InputPublicStates enumerations.
-- =============================================================================

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

-- =============================================================================
-- MODULE STATE
-- Variables that persist between poll cycles.
-- =============================================================================

-- timeSinceUpdate tokens returned by the Inception API after each response.
-- Sent back on the next request so the server only returns events that are
-- newer than the last received update. "0" requests the full current state.
local _tsuArea   = "0"
local _tsuDoors  = "0"
local _tsuInputs = "0"

-- Consecutive failure count and the earliest os.time() at which the next
-- request is permitted. Both reset to 0 after any successful response.
local _failCount  = 0
local _retryAfter = 0

-- Tracks which "missing param" warnings have already been emitted so the log
-- is not flooded with the same message on every poll cycle.
local _missingParamWarned = {}

-- =============================================================================
-- LOGGING HELPERS
-- =============================================================================

-- Returns true if the "Debug Logging" C-Bus user param is set to a truthy value.
local function isDebuggingEnabled()
  return toboolean(GetUserParam(0, DEBUG_PARAM))
end

-- Writes str to the C-Bus log only when debugEnabled is true.
-- Pass the cached dbg flag rather than calling isDebuggingEnabled() again.
local function debuglog(str, debugEnabled)
  if debugEnabled then log(str) end
end

-- =============================================================================
-- C-BUS I/O HELPERS
-- =============================================================================
-- GetUserParam and SetUserParam raise hard Lua errors for params that do not
-- exist in the C-Bus project. Both helpers use pcall to handle this safely.

-- Writes a value to a user param.
-- Silently does nothing if value is nil.
-- Logs a warning once per missing param; suppresses repeats unless debug is on.
local function safeSetUserParam(network, name, value, debugEnabled)
  if value == nil then return end
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
  return s == nil or s == ''
end

-- Decodes an Inception PublicState bitmask integer into a human-readable
-- dash-separated string using the provided flag labels table.
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

-- Called after every failed request. Increments the failure counter and sets
-- _retryAfter to block further requests for an escalating delay period.
local function _recordFailure()
  _failCount = _failCount + 1
  local delay = BACKOFF_DELAYS[math.min(_failCount, #BACKOFF_DELAYS)]
  _retryAfter = os.time() + delay
  log("INCEPTION: offline or no response (failure #" .. _failCount
      .. ") – backing off for " .. delay .. " s.")
end

-- Called after every successful response. Resets backoff state and logs a
-- recovery message if the system was previously in a failure state.
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

-- Sends a POST request to the Inception REST API.
-- Returns the raw response body string on success.
-- Returns nil on HTTP error (logs the error and triggers backoff) or when the
-- response body is empty (normal long-poll timeout — not treated as a failure).
function A.Inception_Post(payload, endpoint)
  local http = require("socket.http")
  local dbg  = isDebuggingEnabled()
  http.TIMEOUT = HTTP_TIMEOUT

  local body, code, _, status = http.request {
    method  = "POST",
    url     = API_ROOT .. "/" .. endpoint,
    headers = {
      ["Accept"]        = "application/json",
      ["Authorization"] = "APIToken " .. api_token,
    },
    body = payload,
  }

  debuglog("INCEPTION POST " .. endpoint
    .. "\n  code:   " .. tostring(code)
    .. "\n  status: " .. tostring(status)
    .. "\n  body:   " .. tostring(body), dbg)

  if code ~= 200 then
    log("INCEPTION: POST error " .. tostring(code) .. " – " .. tostring(body))
    _recordFailure()
    return nil
  elseif isempty(body) then
    -- An empty body means the long-poll timed out with no new events (normal).
    _recordSuccess()
    return nil
  else
    _recordSuccess()
    return body
  end
end

-- =============================================================================
-- PUBLIC API FUNCTIONS
-- =============================================================================

-- Arms or disarms an alarm area.
-- Allowable C_type values: "Disarm", "Arm", "ArmStay", "ArmSleep"
function A.Control_Area(id, C_type)
  local json    = require("json")
  local payload = json.encode({
    Type            = "ControlArea",
    AreaControlType = C_type,
    Entity          = id,
    ExitDelay       = true,
  })

  local res = A.Inception_Post(payload, "control/area/" .. id .. "/activity")
  if res then
    log("INCEPTION: Area Control – " .. C_type .. " – Response: " .. res)
  else
    log("INCEPTION: Area Control – " .. C_type .. " – no response")
  end
  return res
end

-- Decodes an AreaPublicStates bitmask into a readable state string.
function A.areaeval(res)
  return decodeBitmask(res, AREA_FLAGS)
end

-- Decodes a DoorPublicStates bitmask into a readable state string.
function A.dooreval(res)
  return decodeBitmask(res, DOOR_FLAGS)
end

-- Decodes an InputPublicStates bitmask into a readable state string.
function A.inputeval(res)
  return decodeBitmask(res, INPUT_FLAGS)
end

-- Maps entity type strings to their decoder functions.
-- Used by Resident_Poll to look up the correct decoder for each ENTITY_MAP entry.
local EVAL_FN = {
  area  = A.areaeval,
  door  = A.dooreval,
  input = A.inputeval,
}

-- =============================================================================
-- RESIDENT POLL
-- Called on every timer tick by the C-Bus resident script.
-- =============================================================================

function A.Resident_Poll()
  local dbg = isDebuggingEnabled()

  -- ── Backoff check ───────────────────────────────────────────────────────────
  -- If a previous request failed, skip polling until the backoff window expires.
  if os.time() < _retryAfter then
    debuglog("INCEPTION: skipping poll – backing off for another "
             .. (_retryAfter - os.time()) .. " s.", dbg)
    return
  end

  local json = require("json")

  -- ── Build long-poll payload ─────────────────────────────────────────────────
  -- Subscribe to area, door and input state changes in a single request.
  -- The timeSinceUpdate tokens ensure the server only returns events newer
  -- than the last update received for each subscription.
  local payload = json.encode({
    {
      ID          = "CBUS-Areas-Monitor",
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = "AreaState",  timeSinceUpdate = _tsuArea   },
    },
    {
      ID          = "CBUS-Doors-Monitor",
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = "DoorState",  timeSinceUpdate = _tsuDoors  },
    },
    {
      ID          = "CBUS-Input-Monitor",
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = "InputState", timeSinceUpdate = _tsuInputs },
    },
  })

  -- ── Poll the API ────────────────────────────────────────────────────────────
  -- Blocks for up to HTTP_TIMEOUT seconds waiting for a state change event.
  -- Returns nil if nothing changed (normal) or on error (backoff applied).
  local body = A.Inception_Post(payload, "monitor-updates")
  if isempty(body) then return end

  -- ── Parse response ──────────────────────────────────────────────────────────
  local result     = json.pdecode(body)
  local responseId = tostring(result["ID"])
  local stateData  = result["Result"]["stateData"]

  -- Advance the timeSinceUpdate token so the next request only fetches newer events.
  if     responseId == "CBUS-Areas-Monitor" then _tsuArea   = tostring(result["Result"]["updateTime"])
  elseif responseId == "CBUS-Doors-Monitor" then _tsuDoors  = tostring(result["Result"]["updateTime"])
  elseif responseId == "CBUS-Input-Monitor" then _tsuInputs = tostring(result["Result"]["updateTime"])
  end

  -- ── Write state to C-Bus ────────────────────────────────────────────────────
  -- For each updated entity in the response, find its ENTITY_MAP entry and
  -- write the decoded state string to the corresponding C-Bus user param.
  for i = 1, #stateData do
    local entityId = stateData[i]["ID"]
    for _, entry in ipairs(ENTITY_MAP) do
      if entry.id == entityId then
        local evalFn = EVAL_FN[entry.type]
        if evalFn then
          local status = evalFn(stateData[i]["PublicState"])
          safeSetUserParam(CBUS_NETWORK, entry.param, status, dbg)
          debuglog("INCEPTION: " .. entry.param .. " = " .. status, dbg)
        end
        break
      end
    end
  end
end
