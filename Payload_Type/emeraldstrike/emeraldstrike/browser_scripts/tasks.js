function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let data = d["tasks"] || [];
        if(data.length === 0) return {'plaintext': "No scheduled tasks found"};
        let headers = [
            {"plaintext": "#", "type": "number", "width": 70},
            {"plaintext": "task", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            rows.push({
                "rowStyle": {},
                "#": {"plaintext": String(i+1), "cellStyle": {}},
                "task": {"plaintext": data[i], "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Scheduled Tasks (" + data.length + ")"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}