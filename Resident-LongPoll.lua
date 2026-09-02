-- require("user.inception")
-- alarm.Resident_Poll()

-- Inner Range Inception Script for Long Polling Status --

-- ToDo:
-- Implement a nicer way to manage the area ids and mapping to user parameters (and subsequently updating the user parameters)
-- separate out the functions for querying the API

-- need some logic to rate limit the script incase the long poll is unavaliable

------------------------------
     -- User Scripts --
------------------------------

require("user.inception")
require("user.secrets")

------------------------------
     -- User Secrets --
------------------------------

-- Inception URL and Credentials
local api_token = secrets.api_token
local API_ROOT = secrets.API_ROOT

------------------------------
       -- Utilities --
------------------------------

-- Utility Function to check if variable is empty
local function isempty(s)
  return s == nil or s == ''
end

-- Initialise the Time Since Update variable (tsu)
if isempty(tsuarea) then
  tsuarea = "0"
end

if isempty(tsudoors) then
  tsudoors = "0"
end
if isempty(tsuinputs) then
  tsuinputs = "0"
end

------------------------------
--  Inception API Payloads  --
------------------------------

local payload = json.encode(
{
	{
	ID = "CBUS-Areas-Monitor",
	RequestType = "MonitorEntityStates",
	InputData = {
		stateType = "AreaState",
		timeSinceUpdate = tsuarea 
	}
},
{
	ID = "CBUS-Doors-Monitor",
	RequestType = "MonitorEntityStates",
	InputData = {
		stateType = "DoorState",
		timeSinceUpdate = tsudoors
	}
},
{
	ID = "CBUS-Input-Monitor",
	RequestType = "MonitorEntityStates",
	InputData = {
		stateType = "InputState",
		timeSinceUpdate = tsuinputs
	}
}
})	

-- log("Area: " .. tsuarea .. "Doors: " .. tsudoors .. "Inputs: " .. tsuinputs)

------------------------------
	--  Resident Code  --
------------------------------
--log("alarm script is running")

-- Query the API
local body = inception.Inception_Post(payload,"monitor-updates")
--  log(payload)
--	log(body)

-- Process the Response TODO: Clean this Up!

if isempty(body) == false then
  local httptable = json.pdecode(body)

  -- check if the response was related to areas?
  if tostring(httptable["ID"]) == "CBUS-Areas-Monitor" then
	tsuarea = tostring(httptable["Result"]["updateTime"])
	-- Find the matching area ID and translate it to a string
	local numUpdates = table.getn(httptable["Result"]["stateData"])
--	  log("Number of Updates: " .. numUpdates)
--    log(httptable)

    for httptableindex = 1,numUpdates,1
	do
	  if httptable["Result"]["stateData"][httptableindex]["ID"] == secrets.area_id then
		local PublicState = httptable["Result"]["stateData"][httptableindex]["PublicState"]
		local AlarmAreaStatus = inception.areaeval(PublicState)
--		log("Alarm Area Status is: " .. AlarmAreaStatus .. " which was calculated from a Public State ID of " .. PublicState)						
		  -- Set the C-Bus User Parameter
		SetUserParam(0, inception.CBUS_USERPARAM_NAME_ALARMSTATE, AlarmAreaStatus)
--		  	log("We have a match! " .. tostring(httptable["Result"]["stateData"][httptableindex]["ID"]) .. " The Status is now set to " .. tostring(httptable["Result"]["stateData"][httptableindex]["PublicState"]))
	  end
	end
end

  -- check if the response was related to doors?

if tostring(httptable["ID"]) == "CBUS-Doors-Monitor" then
	tsudoors = tostring(httptable["Result"]["updateTime"])    
	-- Find the matching ID and translate it to a string
	local numUpdates = table.getn(httptable["Result"]["stateData"])
	for httptableindex = 1,numUpdates,1
	do
		if httptable["Result"]["stateData"][httptableindex]["ID"] == secrets.front_door_id then
			local PublicState = httptable["Result"]["stateData"][httptableindex]["PublicState"]
			local FrontDoorStatus = inception.dooreval(PublicState)
--			log("Front Door Status is: " .. FrontDoorStatus .. " which was calculated from a Public State ID of " .. PublicState)						
		-- Set the C-Bus User Parameter
	SetUserParam(0, inception.CBUS_USERPARAM_NAME_FRONTDOOR, FrontDoorStatus)
	local strn = string.split(FrontDoorStatus, "-")
	local DoorScreenLabel = tostring(strn[1])
	-- SetCBusLabel(0,56,122,1,'Variant 1',string.sub(DoorScreenLabel, 1, 13))
--	log("Setting C-Bus Label to: " .. tostring(DoorScreenLabel))
	--	log("We have a match! " .. tostring(httptable["Result"]["stateData"][httptableindex]["ID"]) .. " The Status is now set to " .. tostring(httptable["Result"]["stateData"][httptableindex]["PublicState"]))
		end
		if httptable["Result"]["stateData"][httptableindex]["ID"] == secrets.rear_door_id then
			local PublicState = httptable["Result"]["stateData"][httptableindex]["PublicState"]
			local RearDoorStatus = inception.dooreval(PublicState)
--			log("Rear Door Status is: " .. RearDoorStatus .. " which was calculated from a Public State ID of " .. PublicState)						
		-- Set the C-Bus User Parameter
			SetUserParam(0, inception.CBUS_USERPARAM_NAME_REARDOOR, RearDoorStatus)
		--	log("We have a match! " .. tostring(httptable["Result"]["stateData"][httptableindex]["ID"]) .. " The Status is now set to " .. tostring(httptable["Result"]["stateData"][httptableindex]["PublicState"]))
		end
	end
end

-- COMING SOON, INPUT MONITORING --

  -- check if the response was related to inputs?
  if tostring(httptable["ID"]) == "CBUS-Input-Monitor" then
   --log("Look, We found some inputs!")
   -- log(httptable)
	tsuinputs = tostring(httptable["Result"]["updateTime"])
	--build a table of zones we are interested in (todo define the secrets as a table instead)
  local zones = {secrets.zone1, secrets.zone2, secrets.zone3, secrets.zone4, secrets.zone5, secrets.zone6, secrets.zone7, secrets.zone8}
  local numZones = table.getn(zones)
  --log(numZones)
   
  -- Find the matching area ID and translate it to a string
	local numUpdates = table.getn(httptable["Result"]["stateData"])
	  --log("Number of Updates: " .. numUpdates)
    --log(httptable)

    for httptableindex = 1,numUpdates,1
    do
      for zonesindex = 1,numZones,1
      do
      -- log("Reviewing Result: " .. httptableindex .. " against zone id: " .. zonesindex .. " API Result is: " .. httptable["Result"]["stateData"][httptableindex]["ID"] .. " Zone ID is: " .. zones[zonesindex] .. " Is it a match? ")
        if httptable["Result"]["stateData"][httptableindex]["ID"] == zones[zonesindex] then
        local PublicState = httptable["Result"]["stateData"][httptableindex]["PublicState"]
        local AlarmInputStatus = inception.inputeval(PublicState)
--        log("zone" .. zonesindex .. " Status is: " .. AlarmInputStatus .. " which was calculated from a Public State ID of " .. PublicState)						
   			-- log("user param: " .. inception.CBUS_USERPARAM_NAME_ZONES[zonesindex] .. "status: " .. AlarmInputStatus)
          --		  -- Set the C-Bus User Parameter
    SetUserParam(0, inception.CBUS_USERPARAM_NAME_ZONES[zonesindex], AlarmInputStatus)
    --		  --	log("We have a match! " .. tostring(httptable["Result"]["stateData"][httptableindex]["ID"]) .. " The Status is now set to " .. tostring(httptable["Result"]["stateData"][httptableindex]["PublicState"]))
      	end
      end
    end
end

end
