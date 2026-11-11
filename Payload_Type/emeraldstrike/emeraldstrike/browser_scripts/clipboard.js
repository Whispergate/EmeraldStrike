function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        if(d["error"]) return {'plaintext': "Error: " + d["error"]};
        return {'plaintext': d["data"] || d["result"] || "(empty)"};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}