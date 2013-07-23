#include <sourcemod>
#include <sdktools>
#include <smjansson>
#include <cURL>

#include <hs_event_params>

#define VERSION "0.0.1"

#define MAX_EVENT_NAME_LEN 32

#define MAX_POST_LEN 4096

public Plugin:myinfo = {
    name        = "hooktojson",
    author      = "twowordbird",
    description = "Forward hooked function info as JSON via REST",
    version     = VERSION,
}

// event parameter struct
enum _:EventParam
{
    String:EventParamName[MAX_PARAM_NAME_LEN],
    HsParamType:EventParamType
}

// stream_events is our list of event names that we have hooked
//   this list is maintained only as a way to iterate over stream_event_params
new Handle:stream_events
new Handle:stream_event_params

// info waiting to be POSTed
new Handle:json_event_queue
new String:post_data[MAX_POST_LEN]

new bool:curl_busy = false
new Handle:curl

public OnPluginStart()
{
    CreateConVar("hs_version", VERSION, "twb's hooktojson", FCVAR_PLUGIN | FCVAR_SPONLY | FCVAR_REPLICATED | FCVAR_NOTIFY | FCVAR_DONTRECORD)
    InitParamTypes()

    stream_events = CreateArray(MAX_EVENT_NAME_LEN)
    stream_event_params = CreateTrie()

    json_event_queue = CreateArray()

    RegServerCmd("hs_url", Command_Url)
    RegServerCmd("hs_hook", Command_Hook)
    RegServerCmd("hs_unhook", Command_Unhook)
    RegServerCmd("hs_clear", Command_Clear)
}

// hs_url <url>
//     Set the address that JSON data will be posted to. After using this
//     command, any hooked events will be transmitted to this address.
public Action:Command_Url(args)
{
    if (args != 1)
    {
        PrintToServer("Usage: hs_url <url>")
        return Plugin_Handled
    }

    // get rid of current object, if it exists
    if (curl != INVALID_HANDLE)
    {
        CloseHandle(curl)
    }

    // build new curl object
    curl = curl_easy_init()
    if (curl == INVALID_HANDLE)
    {
        PrintToServer("Failed to initialize curl")
        return Plugin_Handled
    }

    curl_easy_setopt_int(curl, CURLOPT_NOSIGNAL, 1)
    curl_easy_setopt_int(curl, CURLOPT_TIMEOUT, 5)
    curl_easy_setopt_int(curl, CURLOPT_CONNECTTIMEOUT, 5)

    decl String:url[128]
    GetCmdArg(1, url, sizeof(url))
    curl_easy_setopt_string(curl, CURLOPT_URL, url)

    return Plugin_Handled
}

// hs_hook <event-name> <parameter1-type> <parameter1-name> ...
//     Hook an event for transmission.
//     <event-name> is taken from this list:
//         http://wiki.alliedmods.net/Counter-Strike:_Global_Offensive_Events
//     <parameterX-type> should be one of the values in param_types_to_names.
//         The use of each of these types is described in hs_event_params.inc.
//     <parameterX-name> should be one of parameters named in the list of
//         events linked above.
// EXAMPLES:
//     hs_hook round_start
//     hs_hook bomb_defused player_name userid
//     hs_hook player_death player_team_name userid player_name userid string weapon
public Action:Command_Hook(args)
{
    // note that num of args must be odd
    if (args < 1 || args % 2 == 0)
    {
        PrintToServer("Usage: hs_hook <event-name> <parameter1-type> <parameter1-name> ...")
        return Plugin_Handled
    }

    decl String:event_name[MAX_EVENT_NAME_LEN]
    GetCmdArg(1, event_name, sizeof(event_name))

    // build list of parameters to monitor

    new event_param_count = (args-1)/2;
    decl event_param[EventParam]
    new Handle:event_params = CreateArray(sizeof(event_param))
    decl String:event_type_name[MAX_PARAM_TYPE_NAME_LEN]

    for (new i = 0; i < event_param_count; ++i)
    {
        GetCmdArg(2*i+2, event_type_name, sizeof(event_type_name))
        GetCmdArg(2*i+3, event_param[EventParamName], sizeof(event_param[EventParamName]))
        event_param[EventParamType] = GetParamTypeForName(event_type_name)
        if (event_param[EventParamType] == HS_INVALID)
        {
            PrintToServer("Type \"%s\" is invalid, ignoring", event_type_name)
        }
        else
        {
            PushArrayArray(event_params, event_param)
        }
    }

    // add parameters to trie
    if (!SetTrieValue(stream_event_params, event_name, event_params, false))
    {
        CloseHandle(event_params)
        PrintToServer("Already monitoring this event, execute \"hs_unhook %s\" first", event_name)
        return Plugin_Handled
    }
    PushArrayString(stream_events, event_name)

    HookEvent(event_name, Event_Hook)

    return Plugin_Handled
}

// hs_unhook <event-name>
//     Stop transmitting <event-name>
public Action:Command_Unhook(args)
{
    if (args != 1)
    {
        PrintToServer("Usage: hs_unhook <event-name>")
        return Plugin_Handled
    }

    decl String:event_name[MAX_EVENT_NAME_LEN]
    GetCmdArg(1, event_name, sizeof(event_name))

    // find index in stream_events and remove
    decl String:buffer[MAX_EVENT_NAME_LEN]
    for (new i = 0; i < GetArraySize(stream_events); ++i)
    {
        GetArrayString(stream_events, i, buffer, sizeof(buffer))
        if (strcmp(event_name, buffer) == 0)
        {
            UnhookEvent(event_name, Event_Hook)

            RemoveFromArray(stream_events, i)

            // delete parameter array and remove from trie
            decl Handle:event_params
            GetTrieValue(stream_event_params, event_name, event_params)
            RemoveFromTrie(stream_event_params, event_name)
            CloseHandle(event_params)

            return Plugin_Handled
        }
    }

    return Plugin_Handled
}

// hs_clear <event-name>
//     Clears all hooks (but does not clear the target address as set by
//     hs_url).
public Action:Command_Clear(args)
{
    if (args != 0)
    {
        PrintToServer("Usage: hs_clear")
        return Plugin_Handled
    }

    // unhook all events
    decl String:event_name[MAX_EVENT_NAME_LEN]
    decl Handle:event_params
    for (new i = 0; i < GetArraySize(stream_events); ++i)
    {
        GetArrayString(stream_events, i, event_name, sizeof(event_name))
        UnhookEvent(event_name, Event_Hook)

        // delete parameter arrays
        GetTrieValue(stream_event_params, event_name, event_params)
        CloseHandle(event_params)
    }

    ClearArray(stream_events)
    ClearTrie(stream_event_params)

    return Plugin_Handled
}

public Action:Event_Hook(Handle:event, const String:event_name[], bool:dontBroadcast)
{
    if (curl != INVALID_HANDLE)
    {
        // get list of parameters
        decl Handle:event_params
        GetTrieValue(stream_event_params, event_name, event_params)

        // build parameters into json
        new Handle:json_event_info = json_object()
        decl event_param[EventParam]
        decl String:param_type_name[MAX_PARAM_TYPE_NAME_LEN]
        decl String:param_key[MAX_PARAM_TYPE_NAME_LEN+MAX_PARAM_NAME_LEN+1]
        for (new i = 0; i < GetArraySize(event_params); ++i)
        {
            GetArrayArray(event_params, i, event_param, sizeof(event_param))
            GetParamNameForType(event_param[EventParamType], param_type_name, sizeof(param_type_name))

            // build json key
            Format(param_key, sizeof(param_key), "%s_%s", param_type_name, event_param[EventParamName])

            switch (event_param[EventParamType])
            {
                case HS_INT:
                {
                    new event_int = GetEventInt(event, event_param[EventParamName])
                    json_object_set_new(json_event_info, param_key, json_integer(event_int))
                }

                case HS_STRING:
                {
                    decl String:event_string[256]
                    GetEventString(event, event_param[EventParamName], event_string, sizeof(event_string))
                    json_object_set_new(json_event_info, param_key, json_string(event_string))
                }
                case HS_PLAYER_NAME:
                {
                    decl String:name[128]
                    GetClientName(GetClientOfUserId(GetEventInt(event, event_param[EventParamName])), name, sizeof(name))
                    json_object_set_new(json_event_info, param_key, json_string(name))
                }
                case HS_PLAYER_TEAM_NAME:
                {
                    decl String:team[128]
                    GetTeamName(GetClientTeam(GetClientOfUserId(GetEventInt(event, event_param[EventParamName]))), team, sizeof(team))
                    json_object_set_new(json_event_info, param_key, json_string(team))
                }
                case HS_TEAM_NAME:
                {
                    decl String:team[128]
                    GetTeamName(GetEventInt(event, event_param[EventParamName]), team, sizeof(team))
                    json_object_set_new(json_event_info, param_key, json_string(team))
                }
            }
        }

        // wrap in json event node
        new Handle:json_event = json_object()
        json_object_set_new(json_event, "event_name", json_string(event_name))
        json_object_set_new(json_event, "event_info", json_event_info)

        // send json
        EnqueueJsonEvent(json_event)
    }

    return Plugin_Continue
}

EnqueueJsonEvent(Handle:json_event)
{
    PushArrayCell(json_event_queue, json_event)

    // send now if the curl handle is available
    if (!curl_busy)
    {
        PostJsonEventQueue()
    }
}

PostJsonEventQueue()
{
    curl_busy = true

    new Handle:json_event_list = json_array()
    for (new i = 0; i < GetArraySize(json_event_queue); ++i)
    {
        json_array_append_new(json_event_list, GetArrayCell(json_event_queue, i))
    }
    ClearArray(json_event_queue)

    new Handle:json_events = json_object()
    json_object_set_new(json_events, "events", json_event_list)
    json_dump(json_events, post_data, sizeof(post_data), 0, false, false, false, true)
    CloseHandle(json_events)

    curl_easy_setopt_string(curl, CURLOPT_POSTFIELDS, post_data)
    curl_easy_perform_thread(curl, OnCurlComplete)
}

public OnCurlComplete(Handle:hndl, CURLcode:code, any:data)
{
    if (code != CURLE_OK)
    {
        new String:error_buffer[256]
        curl_easy_strerror(code, error_buffer, sizeof(error_buffer))
        PrintToServer("Curl request failed: %s", error_buffer)
    }

    // continue processing queue if necessary
    if (GetArraySize(json_event_queue) > 0)
    {
        PostJsonEventQueue()
    }
    else
    {
        curl_busy = false
    }
}
