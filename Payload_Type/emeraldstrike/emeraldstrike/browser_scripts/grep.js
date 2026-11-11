function(task, responses){
    if(task.status.includes("error")){ return {'plaintext': responses.reduce((p,c)=>p+c,"")}; }
    else if(task.completed && responses.length > 0){
        let data = [];
        try{ let p = JSON.parse(responses[0]); if(p["matches"]) data = p["matches"]; }catch(e){}
        if(data.length === 0) return {'plaintext': "No matches found"};
        let headers = [{"plaintext": "file", "type": "string", "fillWidth": true},{"plaintext": "lines", "type": "string", "fillWidth": true}];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            rows.push({"rowStyle": {}, "file": {"plaintext": data[i].file || "", "cellStyle": {}, "copyIcon": true}, "lines": {"plaintext": data[i].lines || "", "cellStyle": {}}});
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Matches"}]};
    }else{ return {'plaintext': "Waiting..."}; }
}
