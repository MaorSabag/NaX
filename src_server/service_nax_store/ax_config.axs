
var metadata = {
    name: "NaXStore",
    description: "NaX persistence store manager - view and clean up cached agent identities and profile overrides"
};

var g_combo      = null;
var g_count_lbl  = null;
var g_entries    = [];

var g_fld_id       = null;
var g_fld_computer = null;
var g_fld_user     = null;
var g_fld_domain   = null;
var g_fld_arch     = null;
var g_fld_pid      = null;
var g_fld_process  = null;
var g_fld_ip       = null;
var g_fld_os       = null;
var g_fld_elevated = null;
var g_fld_sleep    = null;
var g_fld_profile  = null;

function InitService() {
    ax.log("NaX Store Manager service loaded.");

    let combo = form.create_combo();
    g_combo = combo;

    let lblCount = form.create_label("Entries: -");
    g_count_lbl = lblCount;

    form.connect(combo, "currentIndexChanged", function() {
        let agentId = selectedAgentId();
        if (agentId !== "") {
            ax.service_command("nax_store", "details", { agent_id: agentId });
        }
    });

    let fld_id       = form.create_textline(""); fld_id.setReadOnly(true);       g_fld_id = fld_id;
    let fld_computer = form.create_textline(""); fld_computer.setReadOnly(true); g_fld_computer = fld_computer;
    let fld_user     = form.create_textline(""); fld_user.setReadOnly(true);     g_fld_user = fld_user;
    let fld_domain   = form.create_textline(""); fld_domain.setReadOnly(true);   g_fld_domain = fld_domain;
    let fld_arch     = form.create_textline(""); fld_arch.setReadOnly(true);     g_fld_arch = fld_arch;
    let fld_pid      = form.create_textline(""); fld_pid.setReadOnly(true);      g_fld_pid = fld_pid;
    let fld_process  = form.create_textline(""); fld_process.setReadOnly(true);  g_fld_process = fld_process;
    let fld_ip       = form.create_textline(""); fld_ip.setReadOnly(true);       g_fld_ip = fld_ip;
    let fld_os       = form.create_textline(""); fld_os.setReadOnly(true);       g_fld_os = fld_os;
    let fld_elevated = form.create_textline(""); fld_elevated.setReadOnly(true); g_fld_elevated = fld_elevated;
    let fld_sleep    = form.create_textline(""); fld_sleep.setReadOnly(true);    g_fld_sleep = fld_sleep;
    let fld_profile  = form.create_textline(""); fld_profile.setReadOnly(true);  g_fld_profile = fld_profile;

    let selectGrid = form.create_gridlayout();
    selectGrid.addWidget(form.create_label("Agent:"), 0, 0, 1, 1);
    selectGrid.addWidget(combo,                       0, 1, 1, 3);
    selectGrid.addWidget(lblCount,                    1, 0, 1, 1);

    let selectPanel = form.create_panel();
    selectPanel.setLayout(selectGrid);
    let grpSelect = form.create_groupbox("Select Agent", false);
    grpSelect.setPanel(selectPanel);

    let detailGrid = form.create_gridlayout();
    detailGrid.addWidget(form.create_label("Agent ID:"),    0, 0, 1, 1);  detailGrid.addWidget(fld_id,       0, 1, 1, 3);
    detailGrid.addWidget(form.create_label("Computer:"),    1, 0, 1, 1);  detailGrid.addWidget(fld_computer, 1, 1, 1, 1);
    detailGrid.addWidget(form.create_label("Username:"),    1, 2, 1, 1);  detailGrid.addWidget(fld_user,     1, 3, 1, 1);
    detailGrid.addWidget(form.create_label("Domain:"),      2, 0, 1, 1);  detailGrid.addWidget(fld_domain,   2, 1, 1, 1);
    detailGrid.addWidget(form.create_label("Arch:"),        2, 2, 1, 1);  detailGrid.addWidget(fld_arch,     2, 3, 1, 1);
    detailGrid.addWidget(form.create_label("PID / TID:"),   3, 0, 1, 1);  detailGrid.addWidget(fld_pid,      3, 1, 1, 1);
    detailGrid.addWidget(form.create_label("Process:"),     3, 2, 1, 1);  detailGrid.addWidget(fld_process,  3, 3, 1, 1);
    detailGrid.addWidget(form.create_label("Internal IP:"), 4, 0, 1, 1);  detailGrid.addWidget(fld_ip,       4, 1, 1, 1);
    detailGrid.addWidget(form.create_label("OS:"),          4, 2, 1, 1);  detailGrid.addWidget(fld_os,       4, 3, 1, 1);
    detailGrid.addWidget(form.create_label("Elevated:"),    5, 0, 1, 1);  detailGrid.addWidget(fld_elevated, 5, 1, 1, 1);
    detailGrid.addWidget(form.create_label("Sleep:"),       5, 2, 1, 1);  detailGrid.addWidget(fld_sleep,    5, 3, 1, 1);
    detailGrid.addWidget(form.create_label("Profile:"),     6, 0, 1, 1);  detailGrid.addWidget(fld_profile,  6, 1, 1, 3);

    let detailPanel = form.create_panel();
    detailPanel.setLayout(detailGrid);
    let grpDetails = form.create_groupbox("Agent Details", false);
    grpDetails.setPanel(detailPanel);

    let btnDelete  = form.create_button("Delete Selected");
    let btnRefresh = form.create_button("Refresh");
    let btnClear   = form.create_button("Clear All");

    form.connect(btnDelete, "clicked", function() {
        let agentId = selectedAgentId();
        if (agentId === "") {
            ax.show_message("Delete", "Select an agent first.");
            return;
        }
        ax.service_command("nax_store", "delete", { agent_id: agentId });
    });

    form.connect(btnRefresh, "clicked", function() {
        refreshList();
    });

    form.connect(btnClear, "clicked", function() {
        let ok = ax.prompt_confirm("Clear Store", "Delete ALL entries from the persistence store?");
        if (ok) {
            ax.service_command("nax_store", "clear", null);
        }
    });

    let buttonRow = form.create_hlayout();
    buttonRow.addWidget(btnDelete);
    buttonRow.addWidget(btnRefresh);
    buttonRow.addWidget(btnClear);

    let buttonPanel = form.create_panel();
    buttonPanel.setLayout(buttonRow);

    let layout = form.create_vlayout();
    layout.addWidget(grpSelect);
    layout.addWidget(grpDetails);
    layout.addWidget(buttonPanel);

    let dialog = form.create_ext_dialog("NaX Store Manager");
    dialog.setSize(720, 500);
    dialog.setLayout(layout);
}

function refreshList() {
    clearDetailFields();
    ax.service_command("nax_store", "list", null);
}

function clearDetailFields() {
    if (g_fld_id)       g_fld_id.setText("");
    if (g_fld_computer) g_fld_computer.setText("");
    if (g_fld_user)     g_fld_user.setText("");
    if (g_fld_domain)   g_fld_domain.setText("");
    if (g_fld_arch)     g_fld_arch.setText("");
    if (g_fld_pid)      g_fld_pid.setText("");
    if (g_fld_process)  g_fld_process.setText("");
    if (g_fld_ip)       g_fld_ip.setText("");
    if (g_fld_os)       g_fld_os.setText("");
    if (g_fld_elevated) g_fld_elevated.setText("");
    if (g_fld_sleep)    g_fld_sleep.setText("");
    if (g_fld_profile)  g_fld_profile.setText("");
}

function fillDetailFields(d) {
    if (g_fld_id)       g_fld_id.setText(d.id || "");
    if (g_fld_computer) g_fld_computer.setText(d.computer || "-");
    if (g_fld_user)     g_fld_user.setText(d.username || "-");
    if (g_fld_domain)   g_fld_domain.setText(d.domain || "-");
    if (g_fld_arch)     g_fld_arch.setText(d.arch || "-");
    if (g_fld_pid)      g_fld_pid.setText((d.pid || "-") + " / " + (d.tid || "-"));
    if (g_fld_process)  g_fld_process.setText(d.process || "-");
    if (g_fld_ip)       g_fld_ip.setText(d.internal_ip || "-");
    if (g_fld_os)       g_fld_os.setText(d.os_desc || "-");
    if (g_fld_elevated) g_fld_elevated.setText(d.elevated ? "Yes" : "No");
    if (g_fld_sleep)    g_fld_sleep.setText((d.sleep || 0) + "s");

    if (g_fld_profile) {
        if (d.has_profile) {
            let parts = [];
            parts.push("Header: " + (d.beacon_header || "-"));
            parts.push("UA: " + (d.user_agent || "-"));
            parts.push("Rotation: " + (d.rotation || "-"));
            if (d.hosts && d.hosts.length > 0) {
                parts.push("Hosts: " + d.hosts.join(", "));
            }
            parts.push("URIs: GET=" + (d.get_uri_count || 0) + " POST=" + (d.post_uri_count || 0));
            g_fld_profile.setText(parts.join("  |  "));
        } else {
            g_fld_profile.setText("(listener default)");
        }
    }
}

function selectedAgentId() {
    if (g_combo === null || g_entries.length === 0) return "";
    let idx = g_combo.currentIndex();
    if (idx < 0 || idx >= g_entries.length) return "";
    return g_entries[idx].id;
}

function data_handler(data) {
    let response = JSON.parse(data);

    switch (response.action) {
        case "list_result":
            g_entries = response.entries || [];
            if (g_combo !== null) {
                let labels = [];
                for (let i = 0; i < g_entries.length; i++) {
                    let e = g_entries[i];
                    labels.push(e.id + "  |  " + e.computer + "  |  " + e.username + "  |  " + e.profile);
                }
                g_combo.setItems(labels);
            }
            if (g_count_lbl !== null) {
                g_count_lbl.setText("Entries: " + response.count);
            }
            clearDetailFields();
            if (g_entries.length > 0) {
                ax.service_command("nax_store", "details", { agent_id: g_entries[0].id });
            }
            break;

        case "details_result":
            if (response.success) {
                fillDetailFields(response);
            }
            break;

        case "delete_result":
            if (response.success) {
                refreshList();
            } else {
                ax.show_message("Delete Error", response.error || "Unknown error");
            }
            break;

        case "clear_result":
            if (response.success) {
                refreshList();
            } else {
                ax.show_message("Clear Error", response.error || "Unknown error");
            }
            break;

        case "error":
            ax.show_message("NaX Store Error", response.error || "Unknown error");
            break;
    }
}

// (openStoreDialog removed — UI is built in InitService via ext_dialog)
