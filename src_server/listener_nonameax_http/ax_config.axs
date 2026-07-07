
function ListenerUI(mode_create)
{
    // ========= [ helpers ] =========

    function listToArray(w) {
        let a = []; for (let i = 0; i < w.count(); i++) a.push(w.text(i)); return a;
    }
    function headersToObj(w) {
        let o = {};
        for (let i = 0; i < w.count(); i++) { let s = w.text(i); let x = s.indexOf(": "); if (x > 0) o[s.substring(0,x)] = s.substring(x+2); }
        return o;
    }
    function paramsToObj(w) {
        let o = {};
        for (let i = 0; i < w.count(); i++) { let s = w.text(i); let x = s.indexOf("="); if (x > 0) o[s.substring(0,x)] = s.substring(x+1); }
        return o;
    }

    function makeCfgRow(defFmt, defMask, defPlace, defName) {
        let fmt = form.create_combo(); fmt.addItems(["raw","base64","base64url","hex"]);
        if (defFmt) fmt.setCurrentIndex(["raw","base64","base64url","hex"].indexOf(defFmt));
        let mask = form.create_check("Mask"); if (defMask) mask.setChecked(true);
        let place = form.create_combo(); place.addItems(["body","header","cookie","parameter"]);
        if (defPlace) place.setCurrentIndex(["body","header","cookie","parameter"].indexOf(defPlace));
        let name = form.create_textline(defName || "");
        return { fmt: fmt, mask: mask, place: place, name: name };
    }

    function loadCfgRow(cr, obj) {
        if (!obj) return;
        if (obj.format)    cr.fmt.setCurrentIndex(["raw","base64","base64url","hex"].indexOf(obj.format));
        if (obj.mask)      cr.mask.setChecked(true); else cr.mask.setChecked(false);
        if (obj.placement) cr.place.setCurrentIndex(["body","header","cookie","parameter"].indexOf(obj.placement));
        if (obj.name)      cr.name.setText(obj.name); else cr.name.setText("");
    }

    function readCfgRow(cr) {
        return { format: cr.fmt.currentText(), mask: cr.mask.isChecked(), placement: cr.place.currentText(), name: cr.name.text() };
    }

    function addCfgRow(layout, row, label, cr) {
        layout.addWidget(form.create_label(label), row, 0);
        layout.addWidget(cr.fmt,   row, 1);
        layout.addWidget(cr.mask,  row, 2);
        layout.addWidget(cr.place, row, 3);
        layout.addWidget(cr.name,  row, 4);
    }

    // ========= [ Tab 1: Network ] =========

    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create); comboHostBind.clear();
    for (let item of ax.interfaces()) comboHostBind.addItem(item);

    let spinPortBind = form.create_spin();
    spinPortBind.setRange(1, 65535); spinPortBind.setValue(8080); spinPortBind.setEnabled(mode_create);

    let textlineEncryptKey = form.create_textline(ax.random_string(32, "hex"));
    textlineEncryptKey.setEnabled(mode_create);
    let btnKey = form.create_button("Generate"); btnKey.setEnabled(mode_create);
    form.connect(btnKey, "clicked", function() { textlineEncryptKey.setText(ax.random_string(32, "hex")); });

    // ========= [ SSL ] =========

    let certSelector = form.create_selector_file();
    certSelector.setPlaceholder("SSL certificate (.crt / .pem)");
    certSelector.setEnabled(mode_create);
    let keySelector = form.create_selector_file();
    keySelector.setPlaceholder("SSL private key (.key / .pem)");
    keySelector.setEnabled(mode_create);

    let sslLayout = form.create_gridlayout();
    sslLayout.addWidget(certSelector, 0, 0, 1, 3);
    sslLayout.addWidget(keySelector,  1, 0, 1, 3);

    let sslPanel = form.create_panel(); sslPanel.setLayout(sslLayout);

    let sslGroup = form.create_groupbox("Use SSL (HTTPS)", true);
    sslGroup.setPanel(sslPanel);
    sslGroup.setChecked(false);
    sslGroup.setEnabled(mode_create);

    let netLayout = form.create_gridlayout();
    netLayout.addWidget(form.create_label("Host & Port:"), 0, 0);
    netLayout.addWidget(comboHostBind,      0, 1);  netLayout.addWidget(spinPortBind, 0, 2);
    netLayout.addWidget(form.create_label("Encryption Key:"), 1, 0);
    netLayout.addWidget(textlineEncryptKey, 1, 1);  netLayout.addWidget(btnKey, 1, 2);
    netLayout.addWidget(sslGroup, 2, 0, 1, 3);

    let netPanel = form.create_panel(); netPanel.setLayout(netLayout);

    // ========= [ Tab 2: General ] =========

    let textUA        = form.create_textline("Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0");
    textUA.setEnabled(mode_create);
    let textBeaconHdr = form.create_textline("X-Beacon-Id");
    textBeaconHdr.setEnabled(mode_create);
    let comboRotation = form.create_combo(); comboRotation.addItems(["sequential","random"]);
    comboRotation.setEnabled(mode_create);
    let textHosts     = form.create_list(); textHosts.setButtonsEnabled(mode_create); textHosts.addItem("192.168.77.128:8080");
    let btnImport     = form.create_button("Import JSON");
    btnImport.setEnabled(mode_create);
    let btnExport     = form.create_button("Export JSON");
    let textProfileJson = form.create_textmulti("");
    textProfileJson.setEnabled(mode_create);

    let genLayout = form.create_gridlayout();
    genLayout.addWidget(form.create_label("User-Agent:"),  0, 0); genLayout.addWidget(textUA,        0, 1, 1, 2);
    genLayout.addWidget(form.create_label("Beacon ID:"),   1, 0); genLayout.addWidget(textBeaconHdr, 1, 1, 1, 2);
    genLayout.addWidget(form.create_label("Rotation:"),    2, 0); genLayout.addWidget(comboRotation, 2, 1, 1, 2);
    genLayout.addWidget(form.create_label("Hosts:"),       3, 0); genLayout.addWidget(textHosts,     3, 1, 1, 2);
    genLayout.addWidget(btnImport, 4, 0); genLayout.addWidget(btnExport, 4, 1);
    genLayout.addWidget(textProfileJson, 5, 0, 1, 3);

    let genPanel = form.create_panel(); genPanel.setLayout(genLayout);

    // ========= [ Tab 3: GET ] =========

    let textGetUri    = form.create_list(); textGetUri.setButtonsEnabled(mode_create);    textGetUri.addItem("/news/feed");
    let textGetHdrs   = form.create_list(); textGetHdrs.setButtonsEnabled(mode_create);
    let textGetParams = form.create_list(); textGetParams.setButtonsEnabled(mode_create);
    let getMetaCfg    = makeCfgRow("base64", false, "cookie", "__session");
    let getSrvCfg     = makeCfgRow("raw", false, "body", "");
    if (!mode_create) { for (let cr of [getMetaCfg, getSrvCfg]) { cr.fmt.setEnabled(false); cr.mask.setEnabled(false); cr.place.setEnabled(false); cr.name.setEnabled(false); } }

    let getLayout = form.create_gridlayout();
    getLayout.addWidget(form.create_label("URIs:"),    0, 0); getLayout.addWidget(textGetUri,    0, 1, 1, 4);
    getLayout.addWidget(form.create_label("Headers:"), 1, 0); getLayout.addWidget(textGetHdrs,   1, 1, 1, 4);
    getLayout.addWidget(form.create_label("Params:"),  2, 0); getLayout.addWidget(textGetParams, 2, 1, 1, 4);
    addCfgRow(getLayout, 3, "Metadata:", getMetaCfg);
    addCfgRow(getLayout, 4, "Server:",   getSrvCfg);

    let getPanel = form.create_panel(); getPanel.setLayout(getLayout);

    // ========= [ Tab 4: POST ] =========

    let textPostUri  = form.create_list(); textPostUri.setButtonsEnabled(mode_create);  textPostUri.addItem("/api/submit");
    let textPostHdrs = form.create_list(); textPostHdrs.setButtonsEnabled(mode_create);
    let postMetaCfg  = makeCfgRow("raw", false, "header", "X-Request-Id");
    let postOutCfg   = makeCfgRow("raw", false, "body", "");
    let postSrvCfg   = makeCfgRow("raw", false, "body", "");
    if (!mode_create) { for (let cr of [postMetaCfg, postOutCfg, postSrvCfg]) { cr.fmt.setEnabled(false); cr.mask.setEnabled(false); cr.place.setEnabled(false); cr.name.setEnabled(false); } }

    let postLayout = form.create_gridlayout();
    postLayout.addWidget(form.create_label("URIs:"),    0, 0); postLayout.addWidget(textPostUri,  0, 1, 1, 4);
    postLayout.addWidget(form.create_label("Headers:"), 1, 0); postLayout.addWidget(textPostHdrs, 1, 1, 1, 4);
    addCfgRow(postLayout, 2, "Metadata:", postMetaCfg);
    addCfgRow(postLayout, 3, "Output:",   postOutCfg);
    addCfgRow(postLayout, 4, "Server:",   postSrvCfg);

    let postPanel = form.create_panel(); postPanel.setLayout(postLayout);

    // ========= [ Tab 5: Error ] =========

    let spinErrStatus = form.create_spin(); spinErrStatus.setRange(100,599); spinErrStatus.setValue(404);
    spinErrStatus.setEnabled(mode_create);
    let textErrBody   = form.create_textmulti("<!DOCTYPE html>\n<html><body><h1>404 Not Found</h1></body></html>");
    textErrBody.setEnabled(mode_create);
    let textErrHdrs   = form.create_list(); textErrHdrs.setButtonsEnabled(mode_create); textErrHdrs.addItem("Content-Type: text/html");

    let errLayout = form.create_gridlayout();
    errLayout.addWidget(form.create_label("Status:"),  0, 0); errLayout.addWidget(spinErrStatus, 0, 1);
    errLayout.addWidget(form.create_label("Body:"),    1, 0); errLayout.addWidget(textErrBody,   1, 1);
    errLayout.addWidget(form.create_label("Headers:"), 2, 0); errLayout.addWidget(textErrHdrs,   2, 1);

    let errPanel = form.create_panel(); errPanel.setLayout(errLayout);

    // ========= [ Import / Export ] =========

    function loadProfile(cb) {
        if (cb.user_agent)       textUA.setText(cb.user_agent);
        if (cb.beacon_id_header) textBeaconHdr.setText(cb.beacon_id_header);
        if (cb.rotation)         comboRotation.setCurrentIndex(cb.rotation === "random" ? 1 : 0);
        if (cb.hosts && cb.hosts.length) { textHosts.clear(); for (let h of cb.hosts) textHosts.addItem(h); }
        if (cb.get) {
            if (cb.get.uri) { textGetUri.clear(); for (let u of cb.get.uri) textGetUri.addItem(u); }
            let c = cb.get.client || cb.get;
            if (c.headers)    { textGetHdrs.clear(); for (let k in c.headers) textGetHdrs.addItem(k + ": " + c.headers[k]); }
            if (c.parameters) { textGetParams.clear(); for (let k in c.parameters) textGetParams.addItem(k + "=" + c.parameters[k]); }
            if (c.metadata)   loadCfgRow(getMetaCfg, c.metadata);
            let s = cb.get.server || {};
            if (s.output) loadCfgRow(getSrvCfg, s.output);
        }
        if (cb.post) {
            if (cb.post.uri) { textPostUri.clear(); for (let u of cb.post.uri) textPostUri.addItem(u); }
            let c = cb.post.client || cb.post;
            if (c.headers)  { textPostHdrs.clear(); for (let k in c.headers) textPostHdrs.addItem(k + ": " + c.headers[k]); }
            if (c.metadata) loadCfgRow(postMetaCfg, c.metadata);
            if (c.output)   loadCfgRow(postOutCfg, c.output);
            let s = cb.post.server || {};
            if (s.output) loadCfgRow(postSrvCfg, s.output);
        }
        if (cb.server_error) {
            if (cb.server_error.status) spinErrStatus.setValue(cb.server_error.status);
            if (cb.server_error.body)   textErrBody.setText(cb.server_error.body);
            if (cb.server_error.headers) { textErrHdrs.clear(); for (let k in cb.server_error.headers) textErrHdrs.addItem(k + ": " + cb.server_error.headers[k]); }
        }
    }

    form.connect(btnImport, "clicked", function() {
        let path = ax.prompt_open_file("Import Profile JSON", "*.json");
        if (path) {
            let b64 = ax.file_read(path);
            if (b64) {
                let json = ax.decode_data("base64", b64, "");
                try {
                    let p = JSON.parse(json);
                    let cb = (p.callbacks && p.callbacks[0]) ? p.callbacks[0] : p;
                    loadProfile(cb);
                    textProfileJson.setText(json);
                } catch(e) { ax.log_error("Failed to parse JSON: " + e); }
            }
        }
    });

    form.connect(btnExport, "clicked", function() {
        let profile = { callbacks: [{ hosts: listToArray(textHosts), user_agent: textUA.text(),
            beacon_id_header: textBeaconHdr.text(), rotation: comboRotation.currentText(),
            server_error: { status: spinErrStatus.value(), body: textErrBody.text(), headers: headersToObj(textErrHdrs) },
            get: { uri: listToArray(textGetUri), client: { headers: headersToObj(textGetHdrs),
                metadata: readCfgRow(getMetaCfg), parameters: paramsToObj(textGetParams) },
                server: { headers: {}, output: readCfgRow(getSrvCfg) } },
            post: { uri: listToArray(textPostUri), client: { headers: headersToObj(textPostHdrs),
                metadata: readCfgRow(postMetaCfg), output: readCfgRow(postOutCfg) },
                server: { headers: {}, output: readCfgRow(postSrvCfg) } }
        }] };
        let json = JSON.stringify(profile, null, 2);
        textProfileJson.setText(json);
        let path = ax.prompt_save_file("profile.json", "Export Profile JSON", "*.json");
        if (path) ax.file_write_text(path, json);
    });

    // ========= [ Tabs ] =========

    let tabs = form.create_tabs();
    tabs.addTab(netPanel,  "Network");
    tabs.addTab(genPanel,  "General");
    tabs.addTab(getPanel,  "GET");
    tabs.addTab(postPanel, "POST");
    tabs.addTab(errPanel,  "Error");

    let mainLayout = form.create_vlayout();
    if (!mode_create) {
        let editNotice = form.create_label("Listener editing is not available right now. Use the per-agent profile command instead.");
        mainLayout.addWidget(editNotice);
    }
    mainLayout.addWidget(tabs);
    let panel = form.create_panel(); panel.setLayout(mainLayout);

    // ========= [ Container ] =========

    let container = form.create_container();
    container.put("host_bind",       comboHostBind);
    container.put("port_bind",       spinPortBind);
    container.put("encrypt_key",     textlineEncryptKey);
    container.put("ssl",             sslGroup);
    container.put("ssl_cert",        certSelector);
    container.put("ssl_key",         keySelector);
    container.put("callbacks_hosts", textHosts);
    container.put("profile_json",   textProfileJson);

    return { ui_panel: panel, ui_container: container, ui_height: 350, ui_width: 550 };
}
