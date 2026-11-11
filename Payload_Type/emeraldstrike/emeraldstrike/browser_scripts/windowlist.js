function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["windows"]) data = parsed["windows"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "pid", "type": "number", "width": 80},
            {"plaintext": "title", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "pid": {"plaintext": entry["pid"] || "-", "cellStyle": {}},
                "title": {"plaintext": entry["title"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Visible Windows (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
