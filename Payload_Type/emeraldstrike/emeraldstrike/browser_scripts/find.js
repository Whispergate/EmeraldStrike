function(task, responses){
    if(task.status.includes("error")){ return {'plaintext': responses.reduce((p,c)=>p+c,"")}; }
    else if(task.completed && responses.length > 0){
        let data = [];
        try{ let p = JSON.parse(responses[0]); if(p["results"]) data = p["results"]; }catch(e){}
        if(data.length === 0) return {'plaintext': "No matches found"};
        let headers = [{"plaintext": "path", "type": "string", "fillWidth": true},{"plaintext": "size", "type": "size", "width": 120}];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            rows.push({"rowStyle": {}, "path": {"plaintext": data[i].path || "", "cellStyle": {}}, "size": {"plaintext": data[i].size || "", "cellStyle": {}}});
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Search Results (" + data.length + ")"}]};
    }else{ return {'plaintext': "Waiting..."}; }
}
