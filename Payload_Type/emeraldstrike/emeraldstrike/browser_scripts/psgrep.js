function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let data = d["processes"] || [];
        if(data.length === 0) return {'plaintext': "No matching processes"};
        let headers = [
            {"plaintext": "pid", "type": "number", "width": 90},
            {"plaintext": "ppid", "type": "number", "width": 90},
            {"plaintext": "name", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            rows.push({
                "rowStyle": {},
                "pid": {"plaintext": String(data[i]["process_id"]), "cellStyle": {}},
                "ppid": {"plaintext": String(data[i]["parent_process_id"]), "cellStyle": {}},
                "name": {"plaintext": data[i]["name"] || "", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Process Matches (" + data.length + ")"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}