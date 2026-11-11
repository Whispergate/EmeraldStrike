function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let body = d["body"] || "";
        return {'plaintext': "HTTP " + (d["status"]||"?") + " (" + (d["bytes"]||0) + " bytes)\n\n" + body};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}