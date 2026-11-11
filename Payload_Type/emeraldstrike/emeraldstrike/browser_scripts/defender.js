function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let def = d["defender"] || {};
        let ex = def["exclusions"] || {};
        let headers = [
            {"plaintext": "disable_antispyware", "type": "number", "width": 170},
            {"plaintext": "disable_realtime", "type": "number", "width": 150},
            {"plaintext": "path excl.", "type": "number", "width": 110},
            {"plaintext": "ext excl.", "type": "number", "width": 110},
            {"plaintext": "proc excl.", "type": "number", "width": 110},
        ];
        let rows = [{
            "rowStyle": {},
            "disable_antispyware": {"plaintext": String(def["disable_antispyware"]), "cellStyle": {}},
            "disable_realtime": {"plaintext": String(def["disable_realtime"]), "cellStyle": {}},
            "path excl.": {"plaintext": String((ex["paths"]||[]).length), "cellStyle": {}},
            "ext excl.": {"plaintext": String((ex["extensions"]||[]).length), "cellStyle": {}},
            "proc excl.": {"plaintext": String((ex["processes"]||[]).length), "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "Defender Status"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}