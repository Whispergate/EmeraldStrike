function(task, responses){
    if(task.status.includes("error")){
        return {'plaintext': responses.reduce((p,c)=>p+c,"")};
    }else if(task.completed && responses.length > 0){
        let d = {};
        try{ d = JSON.parse(responses[0]); }catch(e){ return {'plaintext': responses[0]}; }
        let addrs = d["addresses"] || [];
        if(addrs.length === 0) return {'plaintext': "No addresses for " + (d["host"]||"")};
        return {'plaintext': (d["host"]||"") + " ->\n" + addrs.join("\n")};
    }else{
        return {'plaintext': "Waiting for response..."};
    }
}