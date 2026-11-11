function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "url", "type": "string", "fillWidth": true},
            {"plaintext": "saved to", "type": "string", "width": 250},
            {"plaintext": "bytes", "type": "number", "width": 110},
        ];
        let rows = [{
            "rowStyle": {},
            "url": {"plaintext": d["url"] || "-", "cellStyle": {}},
            "saved to": {"plaintext": d["path"] || "-", "cellStyle": {}},
            "bytes": {"plaintext": String(d["bytes"]||0), "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "Download " + (d["result"]||"")}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}