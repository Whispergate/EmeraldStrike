function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let pings = d["pings"] || [];
        let headers = [
            {"plaintext": "seq", "type": "number", "width": 70},
            {"plaintext": "ok", "type": "string", "width": 80},
            {"plaintext": "rtt (ms)", "type": "number", "width": 110},
        ];
        let rows = [];
        for(let i = 0; i < pings.length; i++){
            let p = pings[i];
            rows.push({
                "rowStyle": {},
                "seq": {"plaintext": String(i+1), "cellStyle": {}},
                "ok": {"plaintext": p["ok"] ? "yes" : "no", "cellStyle": {}},
                "rtt (ms)": {"plaintext": p["ok"] ? String(p["rtt"]) : "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows,
            "title": "Ping " + (d["host"]||"") + " - " + (d["received"]||0) + "/" + (d["sent"]||0) + " received"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}