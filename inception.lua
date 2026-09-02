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

-- Inception IDs for querying APIs
local area_id       = secrets.area_id
local front_door_id = secrets.front_door_id
local rear_door_id  = secrets.rear_door_id

-- NAC User Parameters
A.CBUS_USERPARAM_NAME_ALARMSTATE = "alarmstate"
A.CBUS_USERPARAM_NAME_FRONTDOOR  = "frontdoor"
A.CBUS_USERPARAM_NAME_REARDOOR   = "reardoor"

-- Zone Names
A.CBUS_USERPARAM_NAME_ZONES = {
  "security_zone1", "security_zone2", "security_zone3", "security_zone4",
  "security_zone5", "security_zone6", "security_zone7", "security_zone8",
}

------------------------------
       -- Utilities --
------------------------------

-- Utility Function to check if variable is empty
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
    return nil
  elseif isempty(body) then
    -- Empty body is normal for a long-poll with no updates in 60 s; not an error.
    return nil
  else
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

------------------------------
--      Resident Poll       --
------------------------------

function A.Resident_Poll()
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

  -- ── Area state ─────────────────────────────────────────────────────────────
  if tostring(httptable["ID"]) == "CBUS-Areas-Monitor" then
    tsuarea = tostring(httptable["Result"]["updateTime"])
    local stateData = httptable["Result"]["stateData"]
    for i = 1, table.getn(stateData) do
      if stateData[i]["ID"] == area_id then
        local status = A.areaeval(stateData[i]["PublicState"])
        SetUserParam(0, A.CBUS_USERPARAM_NAME_ALARMSTATE, status)
      end
    end
  end

  -- ── Door state ─────────────────────────────────────────────────────────────
  if tostring(httptable["ID"]) == "CBUS-Doors-Monitor" then
    tsudoors = tostring(httptable["Result"]["updateTime"])
    local stateData = httptable["Result"]["stateData"]
    for i = 1, table.getn(stateData) do
      local id = stateData[i]["ID"]
      if id == front_door_id then
        SetUserParam(0, A.CBUS_USERPARAM_NAME_FRONTDOOR, A.dooreval(stateData[i]["PublicState"]))
      elseif id == rear_door_id then
        SetUserParam(0, A.CBUS_USERPARAM_NAME_REARDOOR, A.dooreval(stateData[i]["PublicState"]))
      end
    end
  end

  -- ── Input / zone state ─────────────────────────────────────────────────────
  if tostring(httptable["ID"]) == "CBUS-Input-Monitor" then
    tsuinputs = tostring(httptable["Result"]["updateTime"])
    local stateData = httptable["Result"]["stateData"]
    local zones = {
      secrets.zone1, secrets.zone2, secrets.zone3, secrets.zone4,
      secrets.zone5, secrets.zone6, secrets.zone7, secrets.zone8,
    }
    for i = 1, table.getn(stateData) do
      for z = 1, table.getn(zones) do
        if stateData[i]["ID"] == zones[z] then
          local status = A.inputeval(stateData[i]["PublicState"])
          SetUserParam(0, A.CBUS_USERPARAM_NAME_ZONES[z], status)
        end
      end
    end
  end
end
