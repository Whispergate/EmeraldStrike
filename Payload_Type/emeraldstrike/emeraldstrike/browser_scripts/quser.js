function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["sessions"]) data = parsed["sessions"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "session_id", "type": "number", "width": 90},
            {"plaintext": "session_name", "type": "string", "fillWidth": true},
            {"plaintext": "state", "type": "string", "width": 110},
            {"plaintext": "user", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "session_id": {"plaintext": entry["session_id"] || "-", "cellStyle": {}},
                "session_name": {"plaintext": entry["session_name"] || "-", "cellStyle": {}},
                "state": {"plaintext": entry["state"] || "-", "cellStyle": {}},
                "user": {"plaintext": entry["user"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Sessions (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
