function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            let parsed = JSON.parse(responses[0]);
            if(parsed["arp"]) data = parsed["arp"];
        }catch(error){}

        if(data.length === 0) return {'plaintext': "No results"};

        let headers = [
            {"plaintext": "ip", "type": "string", "fillWidth": true},
            {"plaintext": "mac", "type": "string", "fillWidth": true},
            {"plaintext": "type", "type": "number", "width": 80},
        ];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            rows.push({
                "rowStyle": {},
                "ip": {"plaintext": entry["ip"] || "-", "cellStyle": {}},
                "mac": {"plaintext": entry["mac"] || "-", "cellStyle": {}},
                "type": {"plaintext": entry["type"] || "-", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "ARP Table (" + data.length + ")"}]};
    }else{
        return {"plaintext": "Waiting for response..."};
    }
}
