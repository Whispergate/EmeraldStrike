function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "uptime", "type": "string", "fillWidth": true},
            {"plaintext": "days", "type": "number", "width": 90},
            {"plaintext": "hours", "type": "number", "width": 90},
            {"plaintext": "minutes", "type": "number", "width": 100},
            {"plaintext": "seconds", "type": "number", "width": 100},
        ];
        let up = (d.days||0) + "d " + (d.hours||0) + "h " + (d.minutes||0) + "m " + (d.seconds||0) + "s";
        let rows = [{
            "rowStyle": {},
            "uptime": {"plaintext": up, "cellStyle": {}},
            "days": {"plaintext": String(d.days||0), "cellStyle": {}},
            "hours": {"plaintext": String(d.hours||0), "cellStyle": {}},
            "minutes": {"plaintext": String(d.minutes||0), "cellStyle": {}},
            "seconds": {"plaintext": String(d.seconds||0), "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "System Uptime"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}