# AI usage: dsc26-cyb-w06

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

i used Claude (Anthropic's chat assistant) throughout this task:
**Understanding the task:** it explained the README and gave me a general plan
i ran every command and test, made every commit, and pushed myself

## What AI got wrong

i noticed when pytest failed with NotImplementedError on has_hidden_characters and build_messages during test_zero_width_space_does_not_hide_an_override and test_alert_is_wrapped_and_cannot_close_the_tag. iI changed those functions to enforce hidden-character detection and safe <alert-{nonce}> message wrapping with < / > escaping (\u003c / \u003e), then verified with pytest

## In my own words

1. Which leg of the lethal trifecta does stripping markdown images remove, and why does that matter for Hisn?
private data: the copilot sees client data
untrusted content: it reads logs that attackers control
a way out: capabilities such as email tools, URL calls, or model-chosen images
bec Hisn has to examine the private information of the clients and process untrusted log fields controlled by the attacker, since there is no escape route (absence of tools for URLs/emails, nor markdown images selected by the model), the attacker will not be able to exfiltrate the data even after a prompt injection

2. Why does `triage` raise the severity of an alert that contains an injection attempt instead of just warning?
bec detection is a signal, not an impenetrable barrier, as illustrated by a harmless Windows event Log where the benign record System: ELNOUR-DC01 caused a false positive for role_tag out of 20 benign records, a false positive is only a small expenditure of analysis effort and alert noise but missing an attack especially when an attack has been made that manipulates the system to hide or lower the priority of an actual attack, can have serious security consequences