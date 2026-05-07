package io.jenkins.plugins.omniauth;

/**
 * Represents an Azure AD group that has been added to Access Management.
 * OID is the stable identifier used for all matching.
 * Display name is auto-resolved from Graph API on first member login.
 */
public class OmniAuthGroupEntity {

    private String groupOid;
    private String displayName;  // null until first member logs in
    private String label;        // optional admin note
    private String addedAt;
    private String addedBy;

    public OmniAuthGroupEntity() {}

    public OmniAuthGroupEntity(String groupOid, String label, String addedAt, String addedBy) {
        this.groupOid = groupOid;
        this.label = label;
        this.addedAt = addedAt;
        this.addedBy = addedBy;
    }

    public String getGroupOid() { return groupOid != null ? groupOid : ""; }
    public void setGroupOid(String groupOid) { this.groupOid = groupOid; }

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public boolean isResolved() { return displayName != null && !displayName.isEmpty(); }

    /** Human-readable name for UI display — resolved name or label or OID. */
    public String getEffectiveName() {
        if (isResolved()) return displayName;
        if (label != null && !label.isEmpty()) return label;
        return groupOid;
    }

    public String getLabel() { return label != null ? label : ""; }
    public void setLabel(String label) { this.label = label; }

    public String getAddedAt() { return addedAt != null ? addedAt : ""; }
    public void setAddedAt(String addedAt) { this.addedAt = addedAt; }

    public String getAddedBy() { return addedBy != null ? addedBy : ""; }
    public void setAddedBy(String addedBy) { this.addedBy = addedBy; }
}
