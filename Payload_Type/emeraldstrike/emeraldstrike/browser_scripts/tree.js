function(task, responses){
    if(task.status.includes("error")){ return {'plaintext': responses.reduce((p,c)=>p+c,"")}; }
    else if(task.completed && responses.length > 0){
        let data = [];
        try{ let p = JSON.parse(responses[0]); if(p["tree"]) data = p["tree"]; }catch(e){}
        if(data.length === 0) return {'plaintext': "Empty"};
        let headers = [{"plaintext": "name", "type": "string", "fillWidth": true},{"plaintext": "type", "type": "string", "width": 80},{"plaintext": "size", "type": "size", "width": 120}];
        let rows = [];
        for(let i = 0; i < data.length; i++){
            let e = data[i];
            rows.push({"rowStyle": {}, "name": {"plaintext": e.name || "", "startIcon": e.is_dir ? "openFolder" : "file", "cellStyle": {}}, "type": {"plaintext": e.is_dir ? "dir" : "file", "cellStyle": {}}, "size": {"plaintext": e.is_dir ? "" : (e.size || ""), "cellStyle": {}}});
        }
        return {"table":[{"headers": headers, "rows": rows, "title": "Tree"}]};
    }else{ return {'plaintext': "Waiting..."}; }
}
