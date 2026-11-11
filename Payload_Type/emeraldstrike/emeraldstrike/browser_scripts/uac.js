function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let headers = [
            {"plaintext": "enable_lua", "type": "number", "width": 120},
            {"plaintext": "consent_prompt", "type": "number", "width": 140},
            {"plaintext": "secure_ui_paths", "type": "number", "width": 150},
            {"plaintext": "prompt_on_secure_desktop", "type": "number", "width": 210},
            {"plaintext": "level", "type": "number", "width": 90},
        ];
        let rows = [{
            "rowStyle": {},
            "enable_lua": {"plaintext": String(d["enable_lua"]), "cellStyle": {}},
            "consent_prompt": {"plaintext": String(d["consent_prompt"]), "cellStyle": {}},
            "secure_ui_paths": {"plaintext": String(d["secure_ui_paths"]), "cellStyle": {}},
            "prompt_on_secure_desktop": {"plaintext": String(d["prompt_on_secure_desktop"]), "cellStyle": {}},
            "level": {"plaintext": String(d["level"]), "cellStyle": {}},
        }];
        return {"table":[{"headers": headers, "rows": rows, "title": "UAC Settings"}]};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}