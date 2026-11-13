# SSH incident response runbook

Use with the incident register. Times are targets from the priority table (illustrative; agree the real values with the client).

| Priority | Meaning | Respond within |
|---|---|---|
| P1 | Possible compromise (login succeeded after repeated failures) | 15 minutes |
| P2 | High-volume or privileged-account attack | 1 hour |
| P3 | Brute force or spraying with no sign of access | 1 business day |
| P4 | Scanning or low volume | Weekly triage |

## 1. Triage (all priorities)
1. Open the incident; note the source IP, account, time window and the evidence line.
2. Confirm it is real: does the IP belong to a known user, VPN or scanner you operate? If yes, close as false positive and add it to the allow-list.
3. Check whether any login succeeded from that IP: `sudo grep "Accepted" /var/log/auth.log | grep <ip>` (path varies by distribution).
4. Set the status to In progress and record the time (this starts the resolution clock).

## 2. P1: possible compromise
1. Contain: lock the account `sudo passwd -l <user>`, end its sessions `sudo pkill -KILL -u <user>`, and block the IP `sudo ufw deny from <ip>`.
2. Preserve evidence before changing anything else: copy `/var/log/auth.log*` and `last -i` output to a safe location.
3. Investigate: what did the account run after the login? Check shell history, new users, new SSH keys in `~/.ssh/authorized_keys`, cron jobs and listening ports `ss -tulpn`.
4. Eradicate: remove any persistence found; force a new credential `sudo chage -d 0 <user>`; prefer keys or MFA.
5. Escalate to the incident manager and inform the account owner. Record every action with a timestamp.

## 3. P2 and P3: brute force, spraying, distributed attack
1. Block the source: `sudo fail2ban-client set sshd banip <ip>` or a firewall rule.
2. Check targeted accounts: did any existing account receive many attempts? Review the Access Review sheet.
3. For a distributed attack on one account, add account-level throttling and consider restricting SSH to a VPN or allow-list.
4. Link the incident to its problem record (for example PRB-001) and raise or update the change request.

## 4. P4: reconnaissance
1. Monitor; block if the same source returns.
2. Confirm port 22 is meant to be reachable from the internet.

## 5. Close and learn
1. Confirm the fix held: no new incidents from the same source for 24 hours.
2. Update the incident (cause, action, time to resolve) and close it.
3. If the same cause keeps producing incidents, make sure a problem record and a change request exist.
4. Re-run the assessment after changes to evidence the improvement.
