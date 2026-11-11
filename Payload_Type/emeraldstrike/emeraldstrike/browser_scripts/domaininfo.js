function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "hostname", "type": "string", "width": 150},
            {"plaintext": "domain", "type": "string", "fillWidth": true},
            {"plaintext": "fqdn", "type": "string", "fillWidth": true},
            {"plaintext": "workgroup", "type": "string", "width": 130},
            {"plaintext": "os ver", "type": "string", "width": 100},
        ];
        let rows = [{
            "rowStyle": {},
            "hostname": {"plaintext": d["hostname"] || "-", "cellStyle": {}},
            "domain": {"plaintext": d["domain"] || "-", "cellStyle": {}},
            "fqdn": {"plaintext": d["fqdn"] || "-", "cellStyle": {}},
            "workgroup": {"plaintext": d["workgroup"] || "-", "cellStyle": {}},
            "os ver": {"plaintext": (d["ver_major"]||"?") + "." + (d["ver_minor"]||"?"), "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "Domain Info"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}