function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["groups"]) data = parsed["groups"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "comment", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "name": {"plaintext": entry["name"] || "-", "cellStyle": {}},
                "comment": {"plaintext": entry["comment"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Local Groups (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
