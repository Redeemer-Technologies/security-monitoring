# Real-time IIS alert action behavior

Each matching request captures an immutable event before background work is queued. The event contains the rule ID and version, rule name and stage, match timestamp, summary template, recipients, enforcement settings, and the redacted request result. Editing the rule after the match does not alter that event. The version is a deterministic fingerprint of the rule's matching and action settings.

## Cooldown and enforcement

Notification cooldown and enforcement deduplication are independent:

- History and email are claimed once per rule version for the rule's **Evaluation Frequency**. Matches suppressed during that interval are counted. The first notification after the interval reports the prior suppressed count in `IISAlertHistory.ResultCount`, the captured result's `SuppressedMatchCount`, and the email/Lava merge fields `SuppressedMatchCount` and `ResultCount`.
- Request blocking runs for every matching request and is never notification-throttled.
- IP blocking is claimed per rule version and normalized IP address for the configured block duration. A repeat match during that fixed interval does not extend the interval, while another IP is enforced independently.
- Account lockout is claimed per rule version and username for the rule's **Evaluation Frequency**. Another account is enforced independently. Lockout itself is idempotent.
- Changing a rule changes its version and therefore begins new notification and enforcement intervals for the changed configuration.

The in-memory claims are process-local. Multiple web nodes can each create one notification or enforcement attempt, and an application restart clears claims. Persistent IP block writes and account lockout writes are idempotent, so repeated enforcement is safe.

## Background failures and recovery

History, persistent IP blocking, account lockout, summary rendering, and email sending run as separate actions. A failure in one is logged and does not prevent the others from running.

When history is available, its result JSON records `ActionHistory`, `ActionIpBlock`, `ActionAccountLockout`, and `ActionEmail` as `Succeeded`, `Failed`, `NotClaimed`, or `NoRecipients`. Updating these outcome fields is also best-effort and is logged if it fails.

Persistent IP blocking and account lockout are idempotent, so the worker attempts either action up to three times. If all attempts fail, the failure is logged and the enforcement claim is released. Account enforcement can then be claimed by another matching request. The process-local IP block remains effective for its configured duration, so persistent IP enforcement is attempted again after that duration if the address matches again. If the host rejects or cancels a queued event before processing begins, all its claims are released; account work can be reclaimed immediately, while IP persistence waits until the process-local block expires and the address can match again. Notification and email delivery are best-effort and are not retried within a claimed interval because there is no durable idempotency key for those actions; the next match after the interval can create another notification.

History has a required foreign key to the rule. If the rule is deleted before the captured event runs, the missing history is logged with the captured rule ID, name, and version. The captured IP block, account lockout, and email actions still run. A persistent IP block created after rule deletion stores a null rule foreign key while retaining the captured alert name.

Background work uses the ASP.NET hosting queue and is not durable across application termination. Reliable delivery across restarts or coordinated exactly-once delivery across multiple nodes would require a persisted event queue and per-action outcome records.
