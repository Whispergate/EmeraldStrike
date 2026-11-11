function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["connections"]) data = parsed["connections"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "proto", "type": "string", "width": 80},
            {"plaintext": "local", "type": "string", "fillWidth": true},
            {"plaintext": "lport", "type": "number", "width": 80},
            {"plaintext": "remote", "type": "string", "fillWidth": true},
            {"plaintext": "rport", "type": "number", "width": 80},
            {"plaintext": "state", "type": "string", "width": 110},
            {"plaintext": "pid", "type": "number", "width": 70},
            {"plaintext": "process", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "proto": {"plaintext": entry["proto"] || "-", "cellStyle": {}},
                "local": {"plaintext": entry["local"] || "-", "cellStyle": {}},
                "lport": {"plaintext": entry["lport"] || "-", "cellStyle": {}},
                "remote": {"plaintext": entry["remote"] || "-", "cellStyle": {}},
                "rport": {"plaintext": entry["rport"] || "-", "cellStyle": {}},
                "state": {"plaintext": entry["state"] || "-", "cellStyle": {}},
                "pid": {"plaintext": entry["pid"] || "-", "cellStyle": {}},
                "process": {"plaintext": entry["process"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Network Connections (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
