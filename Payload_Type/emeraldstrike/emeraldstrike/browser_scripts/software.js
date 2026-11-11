function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["software"]) data = parsed["software"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "version", "type": "string", "width": 120},
            {"plaintext": "publisher", "type": "string", "fillWidth": true},
            {"plaintext": "hive", "type": "string", "width": 80},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "name": {"plaintext": entry["name"] || "-", "cellStyle": {}},
                "version": {"plaintext": entry["version"] || "-", "cellStyle": {}},
                "publisher": {"plaintext": entry["publisher"] || "-", "cellStyle": {}},
                "hive": {"plaintext": entry["hive"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Installed Software (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
