-- Contains a number of functions to enable communication with Inner Range Inception Alarm Systems
-- todo: prevent this from constanstly smashing the API when there's no response or invalid response

require("user.secrets")
------------------------------
	 -- Script Begins --
------------------------------

-- A is the private package, exposed as 'alarm' library
local A = {}
inception = A

------------------------------
     -- User Settings --
------------------------------

-- Inception URL and Credentials
local api_token = secrets.api_token
local API_ROOT  = secrets.API_ROOT

-- Inception IDs for querying APIs
local area_id = secrets.area_id
local front_door_id = secrets.front_door_id
local rear_door_id = secrets.rear_door_id

-- NAC User Parameters
A.CBUS_USERPARAM_NAME_ALARMSTATE = "alarmstate"
A.CBUS_USERPARAM_NAME_FRONTDOOR = "frontdoor"
A.CBUS_USERPARAM_NAME_REARDOOR = "reardoor"

--Zone Names
A.CBUS_USERPARAM_NAME_ZONES = {"security_zone1","security_zone2","security_zone3","security_zone4","security_zone5","security_zone6","security_zone7","security_zone8"}

------------------------------
       -- Utilities --
------------------------------

-- Utility Function to check if variable is empty
function isempty(s)
  return s == nil or s == ''
end

------------------------------
--  INCEPTION API Functions --
------------------------------

-- Inception POST API

function A.Inception_Post(payload,endpoint)
local http = require("socket.http")
local json = require("json")
http.TIMEOUT = 61 -- prevents errors, long poll is 60sec - allows some buffer
	local body, code, headers, status = http.request {
	method = "POST",
	url = API_ROOT .. "/" .. endpoint,
	headers  =
			{
			["Accept"] = "application/json";
			["Authorization"] = "APIToken " .. api_token;
			},
	body = payload,
	--timeout = 30,
	}
--log("Getting Data from Endpoint URL " .. API_ROOT .. '/' .. endpoint .. '\n'.. 'body:' .. tostring(body) .. '\n' .. 'code:' .. tostring(code) .. '\n' .. 'status:' .. tostring(status))

   if (code ~= 200) then
	   log("Inception post error : "..tostring(code)..","..tostring(body))
	   return
   elseif isempty(body) then
	   return
   else return body
   end
end

-- Inception Control Area
-- Allowable C_Type: Disarm, Arm, ArmStay, ArmSleep

function A.Control_Area(id, C_type)
	local json    = require("json")
	local payload = json.encode({
		Type = "ControlArea",
		AreaControlType = C_type,
		Entity = id,
		ExitDelay = true,
    })

	local endpoint = "/control/area/"..id.."/activity"

	local res = A.Inception_Post(payload,endpoint)
	log("Area Control: " .. C_type .. "Response: " .. res) 
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
