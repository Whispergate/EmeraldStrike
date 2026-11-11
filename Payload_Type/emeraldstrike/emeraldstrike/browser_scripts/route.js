function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["routes"]) data = parsed["routes"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "dest", "type": "string", "fillWidth": true},
            {"plaintext": "mask", "type": "string", "fillWidth": true},
            {"plaintext": "gateway", "type": "string", "fillWidth": true},
            {"plaintext": "metric", "type": "number", "width": 80},
            {"plaintext": "ifindex", "type": "number", "width": 80},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "dest": {"plaintext": entry["dest"] || "-", "cellStyle": {}},
                "mask": {"plaintext": entry["mask"] || "-", "cellStyle": {}},
                "gateway": {"plaintext": entry["gateway"] || "-", "cellStyle": {}},
                "metric": {"plaintext": entry["metric"] || "-", "cellStyle": {}},
                "ifindex": {"plaintext": entry["ifindex"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Routes (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
