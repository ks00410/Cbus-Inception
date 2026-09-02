-- Contains a number of functions to enable communication with Inner Range Inception Alarm Systems

require("user.secrets")

------------------------------
	 -- Script Begins --
------------------------------

-- A is the private package, exposed as 'inception' global so C-Bus can call inception.Resident_Poll()
local A = {}
inception = A

------------------------------
     -- User Settings --
------------------------------

-- Inception URL and Credentials
local api_token = secrets.api_token
local API_ROOT  = secrets.API_ROOT

------------------------------
--   Entity → Param Mapping --
------------------------------

-- Each entry maps a single Inception entity ID (from secrets) to:
--   param  : C-Bus user param name to write the decoded state into
--   eval   : decoder function to call (assigned after functions are defined below)
--   type   : "area" | "door" | "input" — determines which monitor subscription fires
--
-- To add or remove a monitored entity, edit only this table.

local ENTITY_MAP = {
  -- Alarm area
  { id = secrets.area_id,       param = "alarmstate",      type = "area"  },
  -- Doors
  { id = secrets.front_door_id, param = "frontdoor",       type = "door"  },
  { id = secrets.rear_door_id,  param = "reardoor",        type = "door"  },
  -- Zones / inputs
  { id = secrets.zone1,         param = "security_zone1",  type = "input" },
  { id = secrets.zone2,         param = "security_zone2",  type = "input" },
  { id = secrets.zone3,         param = "security_zone3",  type = "input" },
  { id = secrets.zone4,         param = "security_zone4",  type = "input" },
  { id = secrets.zone5,         param = "security_zone5",  type = "input" },
  { id = secrets.zone6,         param = "security_zone6",  type = "input" },
  { id = secrets.zone7,         param = "security_zone7",  type = "input" },
  { id = secrets.zone8,         param = "security_zone8",  type = "input" },
}

-- Backwards-compatible named constants (used by external callers e.g. arm/disarm scripts)
A.CBUS_USERPARAM_NAME_ALARMSTATE = "alarmstate"
A.CBUS_USERPARAM_NAME_FRONTDOOR  = "frontdoor"
A.CBUS_USERPARAM_NAME_REARDOOR   = "reardoor"
A.CBUS_USERPARAM_NAME_ZONES = {
  "security_zone1", "security_zone2", "security_zone3", "security_zone4",
  "security_zone5", "security_zone6", "security_zone7", "security_zone8",
}

------------------------------
       -- Utilities --
------------------------------

-- Returns true when s is nil or an empty string.
local function isempty(s)
  return s == nil or s == ''
end

------------------------------
--      Module State        --
------------------------------

-- Time Since Update tokens for each monitor subscription.
-- Persisted between poll cycles so the server only returns new events.
-- Initialised to "0" to request the full current state on first poll.
local tsuarea   = "0"
local tsudoors  = "0"
local tsuinputs = "0"

-- Backoff state: track consecutive failures and the earliest time the next
-- request is allowed. Reset to zero on any successful response.
local _failCount  = 0
local _retryAfter = 0

-- Delay (seconds) applied after each consecutive failure, capped at the last entry.
-- 1 failure → 30 s, 2 → 60 s, 3 → 120 s, 4+ → 300 s (5 min)
local BACKOFF_DELAYS = { 30, 60, 120, 300 }

local function _recordFailure()
  _failCount = _failCount + 1
  local delay = BACKOFF_DELAYS[math.min(_failCount, #BACKOFF_DELAYS)]
  _retryAfter = os.time() + delay
  log("INCEPTION: offline or no response (failure #" .. _failCount
      .. "). Backing off for " .. delay .. "s.")
end

local function _recordSuccess()
  if _failCount > 0 then
    log("INCEPTION: connection restored after " .. _failCount .. " failure(s).")
  end
  _failCount  = 0
  _retryAfter = 0
end

------------------------------
--  INCEPTION API Functions --
------------------------------

-- Inception POST API

function A.Inception_Post(payload, endpoint)
  local http = require("socket.http")
  http.TIMEOUT = 61 -- long poll is 60 s; allow a small buffer

  local body, code, headers, status = http.request {
    method  = "POST",
    url     = API_ROOT .. "/" .. endpoint,
    headers = {
      ["Accept"]        = "application/json",
      ["Authorization"] = "APIToken " .. api_token,
    },
    body = payload,
  }

  if code ~= 200 then
    log("INCEPTION: POST error " .. tostring(code) .. " – " .. tostring(body))
    _recordFailure()
    return nil
  elseif isempty(body) then
    -- Empty body is normal for a long-poll with no updates in 60 s; not an error.
    _recordSuccess()
    return nil
  else
    _recordSuccess()
    return body
  end
end

-- Inception Control Area
-- Allowable C_Type: Disarm, Arm, ArmStay, ArmSleep

function A.Control_Area(id, C_type)
  local json    = require("json")
  local payload = json.encode({
    Type            = "ControlArea",
    AreaControlType = C_type,
    Entity          = id,
    ExitDelay       = true,
  })

  local endpoint = "control/area/" .. id .. "/activity"
  local res = A.Inception_Post(payload, endpoint)
  if res then
    log("INCEPTION: Area Control – " .. C_type .. " – Response: " .. res)
  else
    log("INCEPTION: Area Control – " .. C_type .. " – no response")
  end
  return res
end

------------------------------
-- Inception Array Decoding --
------------------------------

-- Area Decode Function
function A.areaeval(res)
  local vals = {
    'Armed',
    'Alarm',
    'Entry Delay',
    'Exit Delay',
    'Arm Warning',
    'Defer Disarmed',
    'Detecting Active Inputs',
    'Walk Test Active',
    'Away Arm',
    'Stay Arm',
    'Sleep Arm',
    'Disarmed',
    'Arm Ready',
  }
  local s = ''
  for i = 0, #vals - 1 do
    if bit.band(res, 2^i) > 0 then
      s = (#s > 0 and s .. ' - ' .. vals[i+1]) or vals[i+1]
    end
  end
  return s
end

-- Door Decode Function
function A.dooreval(res)
  local vals = {
    'Unlocked',
    'Open',
    'Locked Out',
    'Forced',
    'Held Open Warning',
    'Held Open Too Long',
    'Breakglass',
    'Reader Tamper',
    'Locked',
    'Closed',
    'Held Response Muted',
    'Battery Low',
    'Lock Offline',
  }
  local s = ''
  for i = 0, #vals - 1 do
    if bit.band(res, 2^i) > 0 then
      s = (#s > 0 and s .. ' - ' .. vals[i+1]) or vals[i+1]
    end
  end
  return s
end

-- Input Decode Function
function A.inputeval(res)
  local vals = {
    'Active',
    'Tamper',
    'Isolated',
    'Mask',
    'Low Battery',
    'Poll Failed',
    'Sealed',
    'Wireless Door Battery Low',
    'Wireless Door Lock Offline',
  }
  local s = ''
  for i = 0, #vals - 1 do
    if bit.band(res, 2^i) > 0 then
      s = (#s > 0 and s .. ' - ' .. vals[i+1]) or vals[i+1]
    end
  end
  return s
end

-- Assign eval functions into ENTITY_MAP now that they are defined.
-- This avoids forward-reference issues while keeping the map at the top.
local function _evalForType(t)
  if t == "area"  then return A.areaeval
  elseif t == "door"  then return A.dooreval
  elseif t == "input" then return A.inputeval
  end
end

------------------------------
--      Resident Poll       --
------------------------------

function A.Resident_Poll()

  -- ── Backoff check ──────────────────────────────────────────────────────────
  if os.time() < _retryAfter then
    local remaining = _retryAfter - os.time()
    log("INCEPTION: skipping poll – backing off for another " .. remaining .. "s.")
    return
  end

  local json = require("json")

  -- Build the long-poll payload subscribing to area, door and input state changes.
  -- timeSinceUpdate tokens are module-level so only new events are returned each cycle.
  local payload = json.encode({
    {
      ID          = "CBUS-Areas-Monitor",
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = "AreaState", timeSinceUpdate = tsuarea },
    },
    {
      ID          = "CBUS-Doors-Monitor",
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = "DoorState", timeSinceUpdate = tsudoors },
    },
    {
      ID          = "CBUS-Input-Monitor",
      RequestType = "MonitorEntityStates",
      InputData   = { stateType = "InputState", timeSinceUpdate = tsuinputs },
    },
  })

  local body = A.Inception_Post(payload, "monitor-updates")
  if isempty(body) then return end

  local httptable = json.pdecode(body)
  local responseId = tostring(httptable["ID"])
  local stateData  = httptable["Result"]["stateData"]

  -- Update the appropriate tsu token for this response type.
  if     responseId == "CBUS-Areas-Monitor" then tsuarea   = tostring(httptable["Result"]["updateTime"])
  elseif responseId == "CBUS-Doors-Monitor" then tsudoors  = tostring(httptable["Result"]["updateTime"])
  elseif responseId == "CBUS-Input-Monitor" then tsuinputs = tostring(httptable["Result"]["updateTime"])
  end

  -- Walk the state updates and write any matching entity's decoded state to C-Bus.
  for i = 1, table.getn(stateData) do
    local entityId = stateData[i]["ID"]
    for _, entry in ipairs(ENTITY_MAP) do
      if entry.id == entityId then
        local evalFn = _evalForType(entry.type)
        if evalFn then
          SetUserParam(0, entry.param, evalFn(stateData[i]["PublicState"]))
        end
        break
      end
    end
  end

end
