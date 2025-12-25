Attack: Super-node Message Injection

Goal:
Force message propagation without valid session.

Method:
Craft FORWARD packet with valid outer header and malformed inner payload.

Impact:
Message delivery disruption and potential crash.

Mitigation:
Authenticated routing headers.