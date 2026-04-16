# OmniAuth Plugin — Future Plans

## Provisioning & Access Request System

### Concept
Self-service access request portal built into Jenkins. No account is created until explicitly approved by an admin. Eliminates ghost accounts and provides a full audit trail.

### User Flows

#### Flow 1: Entra (Microsoft) User
1. User visits unauthenticated provisioning page
2. Clicks "Request Access via Microsoft" — goes through MS OAuth
3. Details pre-filled from Microsoft (name, email, UPN, OID)
4. User fills in: Reason for access, Access duration (time-limited or permanent)
5. Request submitted → pending admin approval

#### Flow 2: Service Account (Legacy/Native)
1. User or admin visits provisioning page
2. Fills in: username, full name, email, reason, access duration
3. Request submitted → pending admin approval
4. On approval: admin sets initial password or auto-generated

### Admin Side (Provisioning submenu in OmniAuth)
- Pending requests queue
- Approve / Reject with optional comment
- On approval: Jenkins user auto-created, permissions configured
- Email notification to admin when new request arrives
- Email notification to requester on approval/rejection

### Time-Limited Access
- Expiry date stored on user (new UserProperty)
- AsyncPeriodicWork checks daily for expired accounts
- Expired accounts disabled or deleted (configurable)
- Reminder email X days before expiry (configurable)

### Settings additions (for Provisioning)
- Enable/disable provisioning portal
- Auto-approve toggle (skip approval for known domains)
- Default access duration
- Admin notification email (critical — currently broken due to classloader)
- Allowed Microsoft tenant domain (e.g. only @company.com)

### Technical Notes
- Unauthenticated provisioning page needs rate limiting (prevent request spam)
- Requests stored in new XML config (similar to OmniAuthGlobalConfig)
- Matrix Auth intercept popup — DROPPED (fragile, over-engineering)
- Email notifications are critical for this feature — must fix jakarta.mail classloader issue first
- New branch: `feature/provisioning`

### Pre-requisites before building
- Fix email notifications (jakarta.mail classloader issue)
- Merge current management UI branch first
