function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "result", "type": "string", "width": 200},
            {"plaintext": "source", "type": "string", "fillWidth": true},
            {"plaintext": "dest", "type": "string", "fillWidth": true},
        ];
        let rows = [{
            "rowStyle": {},
            "result": {"plaintext": d["result"] || "-", "cellStyle": {}},
            "source": {"plaintext": d["source"] || "-", "cellStyle": {}},
            "dest": {"plaintext": d["dest"] || "-", "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "Timestomp"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}