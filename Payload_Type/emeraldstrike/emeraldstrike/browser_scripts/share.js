function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["shares"]) data = parsed["shares"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "path", "type": "string", "fillWidth": true},
            {"plaintext": "type", "type": "number", "width": 100},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "name": {"plaintext": entry["name"] || "-", "cellStyle": {}},
                "path": {"plaintext": entry["path"] || "-", "cellStyle": {}},
                "type": {"plaintext": entry["type"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "SMB Shares (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
