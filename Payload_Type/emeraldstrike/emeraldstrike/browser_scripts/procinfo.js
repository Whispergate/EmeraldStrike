function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "pid", "type": "number", "width": 90},
            {"plaintext": "user", "type": "string", "width": 220},
            {"plaintext": "path", "type": "string", "fillWidth": true},
        ];
        let rows = [{
            "rowStyle": {},
            "pid": {"plaintext": String(d["pid"] || "-"), "cellStyle": {}},
            "user": {"plaintext": d["user"] || "-", "cellStyle": {}},
            "path": {"plaintext": d["path"] || "-", "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "Process Info"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}