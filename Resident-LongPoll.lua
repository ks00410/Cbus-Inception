--[[
  Resident Polling Script for Inner Range Inception Security & Access Control
  Script Type: Resident Script (Sleep interval: 0 or 1 second — uses HTTP long-polling)
  Description: Continuously monitors Inception state updates (areas, doors, inputs, outputs),
               live review events, and activity progress, synchronizing them with C-Bus User Parameters.

  C-Bus User Parameters to create in your C-Bus project / LogicMachine:
    - Debug Logging (Boolean)
    - last_alarm_event (String)
    - alarmstate_detail (String)
    - Area states e.g. alarmstate (String)
    - Door states e.g. garagedoor (String)
    - Input states e.g. security_zone1, security_zone2 (String)
    - Output states e.g. cctv_output (String)
--]]

local inception = require("user.inception")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================
local config = {
  cbus_network = "Ethernet",       -- C-Bus Network name or ID (default: "Ethernet")
  debug_param  = "Debug Logging",  -- C-Bus UserParam for debug toggle (boolean)
  debug        = false,            -- Explicit script debug override (true/false)
  param_prefix = "",               -- Optional prefix for user parameters

  -- (Optional) Explicit UserParam mapping overrides
  cbus_params = {
    -- last_alarm_event  = "Alarm_LastEvent",
    -- alarmstate_detail = "Alarm_Detail",
  },

  -- (Optional) Override or define monitored entities dynamically:
  monitor = {
    areas = {
      { name = "House",              param = "alarmstate"     },
    },
    doors = {
      { name = "Garage Office Door", param = "garagedoor"     },
    },
    inputs = {
      { name = "Hallway",            param = "security_zone1" },
      { name = "Lounge",             param = "security_zone2" },
    },
    outputs = {
      { name = "CCTV",               param = "cctv_output"    },
    },
  }
}

-- Execute single long-poll cycle
inception.Resident_Poll(config)
