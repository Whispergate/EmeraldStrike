function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["drivers"]) data = parsed["drivers"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "base", "type": "string", "width": 180},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "name": {"plaintext": entry["name"] || "-", "cellStyle": {}},
                "base": {"plaintext": entry["base"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Loaded Drivers (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
