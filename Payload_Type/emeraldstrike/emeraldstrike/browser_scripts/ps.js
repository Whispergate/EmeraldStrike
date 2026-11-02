function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(Array.isArray(parsed)){
                data = parsed;
            }
        }catch(error){}

        if(data.length === 0){
            let text = responses[0];
            if(!text || text.trim().length === 0){
                return {'plaintext': 'No processes found'};
            }
            let lines = text.split("\n").filter(l => l.trim().length > 0);
            for(let i = 0; i < lines.length; i++){
                let parts = lines[i].trim().split(/\s+/);
                // C++ output is "pid\tppid\tname"; also tolerate a leading row index
                if(parts.length < 3) continue;
                let pid, ppid, name;
                if(parts.length >= 4 && !isNaN(parseInt(parts[0])) && !isNaN(parseInt(parts[1])) && isNaN(parseInt(parts[2]))){
                    pid = parseInt(parts[1]);
                    ppid = parseInt(parts[2]);
                    name = parts.slice(3).join(" ");
                }else{
                    pid = parseInt(parts[0]);
                    ppid = parseInt(parts[1]);
                    name = parts.slice(2).join(" ");
                }
                if(isNaN(pid) || isNaN(ppid) || name.length === 0) continue;
                data.push({
                    process_id: pid,
                    parent_process_id: ppid,
                    name: name,
                });
            }
        }

        if(data.length === 0){
            return {'plaintext': responses[0]};
        }

        const avProcesses = new Set([
            "mbamservice", "mbamtray", "mbam", "mbamgui",
            "msmpeng", "mpcmdrun", "msascuil", "msseces", "securityhealthservice",
            "securityhealthhost", "securityhealthsystray",
            "avgui", "avguard", "avshadow", "avgsvc", "avgidsagent", "avgwdsvc",
            "avp", "avpui", "kavtray", "kavfswh", "kav",
            "ekrn", "egui", "eguiproxy",
            "bdagent", "bdredline", "bdservicehost", "bdntwrk",
            "savservice", "sophossps", "savapi", "sophos", "sophoshealth",
            "smc", "smcgui", "rtvscan", "ccsvchst", "sepwscsvc",
            "mcshield", "mctray", "mcuicnt", "mcuimgr", "masvc",
            "coreserviceshell", "pccntmon", "ntrtscan", "tmlisten", "tmbmsrv",
            "ds_monitor", "ds_agent", "ds_notifier",
            "fmon", "fsav", "fsma", "fssm",
            "cmdagent", "cfp", "cavwp", "cis",
            "a2service", "a2guard",
            "dwservice", "dwengine",
            "wrsa", "wrsssdk",
            "fortitray", "forticlient",
            "avastsvc", "avastui", "avgnt",
            "cyserver", "cyoptics", "cytray",
            "csfalconservice", "csfalconcontainer", "csagent",
            "senseir", "sensecncproxy", "sensesampleuploader", "mssense",
            "xagt", "xagtnotif",
            "cbdefense", "cbcomms", "cbstream", "repux", "repmgr",
            "taniumclient", "taniumdetectengine",
            "sentinel", "sentinelagent", "sentinelone",
            "nortonsecurity", "ns",
            "panda_url_filtering", "pavfires", "psanhost",
            "immunetprotect", "clamav", "clamd", "freshclam",
            "fsgk32", "fsav32", "fsorsp",
            "vsserv", "vsservppl",
            "savadminservice", "hmpalert", "sophosfilescanner",
            "intercept", "sophosntpservice", "sophoscleanup",
            "eectrl", "esensor",
            "sfc", "sfctlcom",
            "elastic-agent", "elastic-endpoint", "filebeat", "winlogbeat", "metricbeat",
            "osqueryd", "osqueri",
            "wazuh-agent", "ossec-agent",
            "splunkd", "splunkforwarder", "universalforwarder",
            "qualysagent",
            "nessuscli", "nessusd",
            "snort", "suricata",
            "sysmon", "sysmon64",
        ]);

        const adminTools = new Set([
            "procexp", "procexp64", "procmon", "procmon64",
            "autoruns", "autoruns64", "autorunsc", "autorunsc64",
            "tcpview", "tcpview64",
            "wireshark", "dumpcap", "tshark",
            "fiddler", "charles",
            "processhacker", "systeminformer",
            "x64dbg", "x32dbg", "ollydbg", "windbg", "dbgview",
            "ida", "ida64", "idaq", "idaq64", "idat", "idat64",
            "ghidra", "ghidrarun",
            "dnspy", "dotpeek",
            "regmon", "filemon",
            "pestudio", "die", "cff explorer",
            "apimonitor", "apimonitor-x64",
            "hxd", "010editor",
            "perfmon", "resmon", "mmc",
            "logparser",
            "powershell_ise",
            "msconfig",
        ]);

        const systemProcs = new Set([
            "system", "registry", "smss", "csrss", "wininit", "services",
            "lsass", "svchost", "winlogon", "dwm", "explorer",
            "fontdrvhost", "sihost", "taskhostw", "runtimebroker",
            "ctfmon", "conhost", "dllhost",
            "spoolsv", "searchindexer", "wudfhost",
            "secure system", "[system process]",
            "lsaiso", "lsaiso.exe",
        ]);

        function classify(name){
            let lower = name.toLowerCase().replace(/\.exe$/, "");
            if(avProcesses.has(lower)) return "av";
            if(adminTools.has(lower)) return "admin";
            if(systemProcs.has(lower)) return "system";
            return "normal";
        }

        const colorMap = {
            "av":     "indianred",
            "admin":  "rgb(106,255,255)",
            "system": "cornflowerblue",
            "normal": "",
        };

        let headers = [
            {"plaintext": "actions", "type": "button", "width": 80, "disableSort": true},
            {"plaintext": "pid", "type": "number", "width": 100},
            {"plaintext": "ppid", "type": "number", "width": 100},
            {"plaintext": "user", "type": "string", "width": 200},
            {"plaintext": "name", "type": "string", "fillWidth": true},
        ];
        let rows = [];

        for(let i = 0; i < data.length; i++){
            let proc = data[i];
            let cls = classify(proc.name);
            let color = colorMap[cls];
            let rowStyle = color ? {"backgroundColor": color} : {};

            let nameCell = {"plaintext": proc.name, "cellStyle": {}};
            if(cls === "av"){
                nameCell["startIcon"] = "warning";
                nameCell["startIconHoverText"] = "Security Product";
                nameCell["startIconColor"] = "white";
            } else if(cls === "admin"){
                nameCell["startIcon"] = "search";
                nameCell["startIconHoverText"] = "Admin/Debug Tool";
            }

            let menuItems = [{
                "name": "Kill",
                "type": "task",
                "startIcon": "kill",
                "startIconColor": "indianred",
                "ui_feature": "kill",
                "parameters": JSON.stringify({"pid": proc.process_id}),
                "hoverText": "Terminate this process",
            },{
                "name": "Inject",
                "type": "task",
                "startIcon": "inject",
                "ui_feature": "inject",
                "parameters": JSON.stringify({"pid": proc.process_id}),
                "hoverText": "Inject shellcode into this process",
            }];

            let row = {
                "rowStyle": rowStyle,
                "pid":  {"plaintext": proc.process_id, "cellStyle": {}},
                "ppid": {"plaintext": proc.parent_process_id, "cellStyle": {}},
                "user": {"plaintext": proc.user || "-", "cellStyle": {}},
                "name": nameCell,
                "actions": {"button": {
                    "name": "",
                    "type": "menu",
                    "value": menuItems,
                }},
            };
            rows.push(row);
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Process Listing (" + data.length + " processes)",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
