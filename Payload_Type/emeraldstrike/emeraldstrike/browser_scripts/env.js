function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let parsed = {};
        try{ parsed = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let env = parsed["env"] || {};
        let keys = Object.keys(env);
        if(keys.length === 0) return {'plaintext': 'No environment variables found'};
        let headers = [
            {"plaintext": "variable", "type": "string", "width": 300},
            {"plaintext": "value", "type": "string", "fillWidth": true},
        ];
        let rows = [];
        const sensitive = ["api_key","apikey","secret","password","token","credential","private_key","connectionstring"];
        for(let i = 0; i < keys.length; i++){
            let key = keys[i];
            let lower = key.toLowerCase();
            let isSensitive = false;
            for(let s of sensitive){ if(lower.includes(s)){ isSensitive = true; break; } }
            let nameCell = {"plaintext": key, "cellStyle": {}};
            if(isSensitive){
                nameCell["startIcon"] = "key";
                nameCell["startIconColor"] = "goldenrod";
                nameCell["startIconHoverText"] = "Potentially sensitive";
            }
            rows.push({
                "rowStyle": isSensitive ? {"backgroundColor": "rgba(218,165,32,0.15)"} : {},
                "variable": nameCell,
                "value": {"plaintext": env[key] || "", "cellStyle": {}},
            });
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Environment Variables (" + rows.length + ")"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}