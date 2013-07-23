#define MAX_PARAM_TYPE_NAME_LEN 32
#define MAX_PARAM_NAME_LEN 32

enum HsParamType
{
    HS_INT = 0,
    HS_STRING,
    HS_PLAYER_NAME,
    HS_PLAYER_TEAM_NAME,
    HS_TEAM_NAME,
    HS_INVALID
}

new String:param_types_to_names[][MAX_PARAM_TYPE_NAME_LEN] =
{
    "int",
    "string",
    "player_name",      // converts userid into the player's name
    "player_team_name", // converts userid into the player's team name
    "team_name",        // converts teamid into team name (e.g., in the round_end event)
    "invalid"
}

new Handle:param_names_to_types

stock InitParamTypes()
{
    param_names_to_types = CreateTrie()
    SetTrieValue(param_names_to_types, "int", HS_INT)
    SetTrieValue(param_names_to_types, "string", HS_STRING)
    SetTrieValue(param_names_to_types, "player_name", HS_PLAYER_NAME)
    SetTrieValue(param_names_to_types, "player_team_name", HS_PLAYER_TEAM_NAME)
    SetTrieValue(param_names_to_types, "team_name", HS_TEAM_NAME)
}

stock HsParamType:GetParamTypeForName(const String:param_name[])
{
    decl HsParamType:param_type
    if (!GetTrieValue(param_names_to_types, param_name, param_type))
    {
        param_type = HS_INVALID
    }

    return param_type
}

stock GetParamNameForType(HsParamType:param_type, String:param_type_name[], max_size)
{
    strcopy(param_type_name, max_size, param_types_to_names[param_type])
}
