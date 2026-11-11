function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "path", "type": "string", "fillWidth": true},
            {"plaintext": "size", "type": "size", "width": 110},
            {"plaintext": "created", "type": "string", "width": 150},
            {"plaintext": "modified", "type": "string", "width": 150},
            {"plaintext": "accessed", "type": "string", "width": 150},
        ];
        let rows = [{
            "rowStyle": {},
            "path": {"plaintext": d["path"] || "-", "cellStyle": {}},
            "size": {"plaintext": d["exists"] ? String(d["size"]) : "-", "cellStyle": {}},
            "created": {"plaintext": d["created"] || "-", "cellStyle": {}},
            "modified": {"plaintext": d["modified"] || "-", "cellStyle": {}},
            "accessed": {"plaintext": d["accessed"] || "-", "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": d["exists"] ? "File Info" : "Not Found"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}