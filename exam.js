let rows = 4;
for(let i = rows; i > 0; i--){
    let pattern = "";

    for(let j = 1; j<= i; j++){
        pattern += "* ";
    }
    document.write(pattern+ "<br>");   
}