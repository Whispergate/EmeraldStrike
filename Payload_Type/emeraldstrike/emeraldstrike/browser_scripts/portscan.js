function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let open = d["open_ports"] || [];
        let headers = [
            {"plaintext": "port", "type": "number", "width": 110},
            {"plaintext": "state", "type": "string", "width": 110},
        ];
        let rows = [];
        for(let i = 0; i < open.length; i++){
            rows.push({
                "rowStyle": {},
                "port": {"plaintext": String(open[i]["port"]), "cellStyle": {}},
                "state": {"plaintext": open[i]["state"] || "open", "cellStyle": {}},
            });
        }
        if(rows.length === 0) rows.push({
            "rowStyle": {},
            "port": {"plaintext": "-", "cellStyle": {}},
            "state": {"plaintext": "no open ports", "cellStyle": {}},
        });
        return {"table":[{"headers": headers, "rows": rows,
            "title": (d["host"]||"") + " (" + (d["ip"]||"") + ") - " + (d["open"]||0) + " open / " + (d["scanned"]||0) + " scanned"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}